import {
  copyFileSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import esmock from "esmock";
import { assert, describe, it } from "poku";
import sinon from "sinon";

import {
  getRecordedActivities,
  resetRecordedActivities,
  setDryRunMode,
} from "../ecosystems/utils.js";
import { auditBom } from "../stages/postgen/auditBom.js";
import { postProcess } from "../stages/postgen/postgen.js";
import {
  cacheDisableFixtureDir,
  getProp,
  mcpFixtureDir,
  pyLockSmokeFixtureDir,
  uvSmokeFixtureDir,
} from "./bomTestHelpers.poku.js";
import { createBom } from "./index.js";
import { createNodejsBom } from "./jsBom.js";
import { createCsharpBom, createPythonBom } from "./managedBom.js";

describe("managedBom", () => {
  describe("createBom() Collider lock support", () => {
    it("preserves Collider integrity metadata and dependency nodes in the BOM", async () => {
      const tmpDir = mkdtempSync(join(tmpdir(), "cdxgen-collider-"));
      writeFileSync(
        join(tmpDir, "collider.lock"),
        JSON.stringify(
          {
            version: 1,
            dependencies: {
              fmt: {
                version: "11.0.2",
                wrap_hash: `sha256:${"a".repeat(64)}`,
                origin: "https://packages.example.com/collider/v2/",
              },
            },
            packages: {
              fast_float: {
                version: "8.0.2",
                wrap_hash: `sha256:${"b".repeat(64)}`,
                origin: "https://wrapdb.mesonbuild.com/v2/",
              },
            },
          },
          null,
          2,
        ),
      );
      try {
        const bomNSData = await createBom(tmpDir, {
          failOnError: true,
          installDeps: false,
          multiProject: false,
          projectType: ["collider"],
          specVersion: 1.7,
        });
        const bomJson = bomNSData?.bomJson || {};
        const fmtComponent = (bomJson.components || []).find(
          (component) => component.name === "fmt",
        );
        const transitiveComponent = (bomJson.components || []).find(
          (component) => component.name === "fast_float",
        );
        assert.ok(fmtComponent);
        assert.ok(transitiveComponent);
        assert.deepStrictEqual(
          getProp(fmtComponent, "cdx:collider:origin"),
          "https://packages.example.com/collider/v2/",
        );
        assert.deepStrictEqual(
          getProp(fmtComponent, "cdx:collider:hasWrapHash"),
          "true",
        );
        assert.deepStrictEqual(
          getProp(transitiveComponent, "cdx:collider:dependencyKind"),
          "transitive",
        );
        assert.deepStrictEqual(fmtComponent.hashes, [
          {
            alg: "SHA-256",
            content: "a".repeat(64),
          },
        ]);
        assert.deepStrictEqual(fmtComponent.externalReferences, [
          {
            type: "distribution",
            url: "https://packages.example.com/collider/v2/",
          },
        ]);
        const parentDependency = (bomJson.dependencies || []).find(
          (dependency) =>
            dependency.ref === bomJson.metadata.component["bom-ref"],
        );
        assert.ok(parentDependency);
        assert.deepStrictEqual(parentDependency.dependsOn, [
          "pkg:generic/fmt@11.0.2",
        ]);
        assert.ok(
          (bomJson.dependencies || []).some(
            (dependency) =>
              dependency.ref === "pkg:generic/fmt@11.0.2" &&
              !dependency.dependsOn?.length,
          ),
        );
        assert.ok(
          (bomJson.dependencies || []).some(
            (dependency) =>
              dependency.ref === "pkg:generic/fast_float@8.0.2" &&
              !dependency.dependsOn?.length,
          ),
        );
      } finally {
        rmSync(tmpDir, { force: true, recursive: true });
      }
    });
  });

  describe("createBom() MCP inventory support", () => {
    it("catalogs MCP services, primitives, and audit findings for JavaScript projects", async () => {
      const options = {
        bomAudit: true,
        bomAuditCategories: "mcp-server",
        bomAuditMinSeverity: "low",
        failOnError: true,
        installDeps: false,
        multiProject: false,
        projectType: ["js"],
        specVersion: 1.7,
      };
      const bomNSData = await createBom(mcpFixtureDir, options);
      const processedBomNSData = postProcess(bomNSData, options, mcpFixtureDir);
      const bomJson = processedBomNSData?.bomJson || {};
      const officialSdk = (bomJson.components || []).find(
        (component) =>
          component.purl ===
          "pkg:npm/%40modelcontextprotocol/server@2.0.0-alpha.0",
      );
      const wrapperSdk = (bomJson.components || []).find(
        (component) => component.purl === "pkg:npm/%40acme/mcp-server@0.1.0",
      );
      assert.ok(officialSdk);
      assert.ok(
        officialSdk.tags?.includes("official-mcp-sdk"),
        "expected official MCP SDK tags",
      );
      assert.ok(wrapperSdk);
      assert.ok(
        wrapperSdk.properties?.some(
          (property) =>
            property.name === "cdx:mcp:official" && property.value === "false",
        ),
        "expected non-official MCP wrapper signal",
      );
      assert.strictEqual((bomJson.services || []).length, 2);
      const unsafeService = (bomJson.services || []).find(
        (service) => service.name === "unsafe-http-server",
      );
      const authService = (bomJson.services || []).find(
        (service) => service.name === "auth-http-server",
      );
      assert.ok(unsafeService);
      assert.strictEqual(unsafeService.authenticated, false);
      assert.ok(authService);
      assert.strictEqual(authService.authenticated, true);
      assert.ok(
        (bomJson.dependencies || []).some(
          (dependency) =>
            dependency.ref === unsafeService["bom-ref"] &&
            dependency.provides.length >= 1,
        ),
      );
      const findings = await auditBom(bomJson, {
        bomAuditCategories: "mcp-server",
        bomAuditMinSeverity: "low",
      });
      assert.ok(findings.some((finding) => finding.ruleId === "MCP-001"));
      assert.ok(findings.some((finding) => finding.ruleId === "MCP-002"));
      assert.ok(findings.some((finding) => finding.ruleId === "MCP-003"));
    });

    it("supports the ai-inventory audit category alias for MCP discovery", async () => {
      const options = {
        bomAudit: true,
        bomAuditCategories: "ai-inventory",
        bomAuditMinSeverity: "low",
        failOnError: true,
        installDeps: false,
        multiProject: false,
        projectType: ["js"],
        specVersion: 1.7,
      };
      const bomNSData = await createBom(mcpFixtureDir, options);
      const processedBomNSData = postProcess(bomNSData, options, mcpFixtureDir);
      const bomJson = processedBomNSData?.bomJson || {};
      assert.ok(
        (bomJson.services || []).some(
          (service) => service.name === "unsafe-http-server",
        ),
      );
      const findings = await auditBom(bomJson, {
        bomAuditCategories: "ai-inventory",
        bomAuditMinSeverity: "low",
      });
      assert.ok(findings.some((finding) => finding.ruleId === "MCP-001"));
    });

    it("supports the dedicated mcp project type alias", async () => {
      const options = {
        bomAudit: false,
        failOnError: true,
        installDeps: false,
        multiProject: false,
        projectType: ["mcp"],
        specVersion: 1.7,
      };
      const bomNSData = await createBom(mcpFixtureDir, options);
      const processedBomNSData = postProcess(bomNSData, options, mcpFixtureDir);
      const bomJson = processedBomNSData?.bomJson || {};
      assert.ok(
        (bomJson.services || []).some(
          (service) => service.name === "unsafe-http-server",
        ),
      );
      assert.ok(
        (bomJson.components || []).some(
          (component) =>
            component.purl ===
            "pkg:npm/%40modelcontextprotocol/server@2.0.0-alpha.0",
        ),
      );
    });

    it("flags disabled setup caches for npm, Python, and Cargo fixtures", async () => {
      const options = {
        bomAudit: true,
        bomAuditCategories: "ci-permission",
        bomAuditMinSeverity: "low",
        failOnError: true,
        includeFormulation: true,
        installDeps: false,
        multiProject: true,
        projectType: ["js", "python", "cargo", "github"],
        specVersion: 1.7,
      };
      const bomNSData = await createBom(cacheDisableFixtureDir, options);
      const processedBomNSData = postProcess(
        bomNSData,
        options,
        cacheDisableFixtureDir,
      );
      const bomJson = processedBomNSData?.bomJson || {};
      const setupNodeComponent = (bomJson.components || []).find(
        (component) =>
          getProp(component, "cdx:github:action:uses") ===
          "actions/setup-node@v4",
      );
      const setupPythonComponent = (bomJson.components || []).find(
        (component) =>
          getProp(component, "cdx:github:action:uses") ===
          "actions/setup-python@v5",
      );
      const setupRustComponent = (bomJson.components || []).find(
        (component) =>
          getProp(component, "cdx:github:action:uses") ===
          "moonrepo/setup-rust@v1",
      );
      const npmComponent = (bomJson.components || []).find((component) =>
        component.purl?.startsWith("pkg:npm/left-pad@1.3.0"),
      );
      const pythonComponent = (bomJson.components || []).find((component) =>
        component.purl?.startsWith("pkg:pypi/anyio@4.6.0"),
      );
      const cargoComponent = (bomJson.components || []).find(
        (component) =>
          component.name === "git-crate" &&
          getProp(component, "cdx:cargo:git") ===
            "https://github.com/acme/git-crate.git",
      );
      const cargoRunComponent = (bomJson.components || []).find((component) =>
        component.properties?.some(
          (property) =>
            property.name === "cdx:github:step:cargoSubcommands" &&
            property.value === "build",
        ),
      );
      assert.ok(setupNodeComponent, "expected setup-node workflow component");
      assert.ok(
        setupPythonComponent,
        "expected setup-python workflow component",
      );
      assert.ok(setupRustComponent, "expected setup-rust workflow component");
      assert.strictEqual(
        getProp(setupNodeComponent, "cdx:github:action:disablesBuildCache"),
        "true",
      );
      assert.strictEqual(
        getProp(setupPythonComponent, "cdx:github:action:disablesBuildCache"),
        "true",
      );
      assert.strictEqual(
        getProp(setupRustComponent, "cdx:github:action:disablesBuildCache"),
        "true",
      );
      assert.strictEqual(
        getProp(setupRustComponent, "cdx:github:action:buildCacheEcosystem"),
        "cargo",
      );
      assert.strictEqual(
        getProp(setupRustComponent, "cdx:github:action:buildCacheDisableInput"),
        "cache",
      );
      assert.ok(npmComponent, "expected npm dependency from package-lock");
      assert.ok(pythonComponent, "expected PyPI dependency from uv.lock");
      assert.ok(cargoComponent, "expected Cargo dependency from Cargo.toml");
      assert.ok(cargoRunComponent, "expected Cargo run step component");
      assert.strictEqual(
        getProp(npmComponent, "cdx:npm:manifestSourceType"),
        "url",
      );
      assert.strictEqual(
        getProp(pythonComponent, "cdx:pypi:manifestSourceType"),
        "url",
      );
      assert.strictEqual(
        getProp(cargoComponent, "cdx:cargo:git"),
        "https://github.com/acme/git-crate.git",
      );
      assert.strictEqual(
        getProp(cargoComponent, "cdx:cargo:gitBranch"),
        "main",
      );
      assert.strictEqual(
        getProp(cargoRunComponent, "cdx:github:step:usesCargo"),
        "true",
      );

      const findings = await auditBom(bomJson, {
        bomAuditCategories: "ci-permission",
        bomAuditMinSeverity: "low",
      });
      assert.ok(
        findings.some((finding) => finding.ruleId === "CI-022"),
        "expected npm disabled cache finding",
      );
      assert.ok(
        findings.some((finding) => finding.ruleId === "CI-023"),
        "expected Python disabled cache finding",
      );
      assert.ok(
        findings.some((finding) => finding.ruleId === "CI-024"),
        "expected Cargo disabled cache finding",
      );
    });

    it("requires explicit opt-in for AI inventory in js and python scans", async () => {
      const tmpDir = mkdtempSync(join(tmpdir(), "cdxgen-ai-inventory-"));
      const writeGgufFixture = (filePath) => {
        const chunks = [];
        const pushU32 = (value) => {
          const buffer = Buffer.alloc(4);
          buffer.writeUInt32LE(value);
          chunks.push(buffer);
        };
        const pushU64 = (value) => {
          const buffer = Buffer.alloc(8);
          buffer.writeBigUInt64LE(BigInt(value));
          chunks.push(buffer);
        };
        const pushString = (value) => {
          const buffer = Buffer.from(value, "utf-8");
          pushU64(buffer.length);
          chunks.push(buffer);
        };
        const pushKeyValue = (key, type, writer) => {
          pushString(key);
          pushU32(type);
          writer();
        };
        chunks.push(Buffer.from("GGUF"));
        pushU32(3);
        pushU64(0);
        pushU64(4);
        pushKeyValue("general.name", 8, () => pushString("TinyLlama-1.1B"));
        pushKeyValue("general.license", 8, () => pushString("Apache-2.0"));
        pushKeyValue("llama.context_length", 4, () => pushU32(8192));
        pushKeyValue("general.file_type", 4, () => pushU32(15));
        writeFileSync(filePath, Buffer.concat(chunks));
      };
      mkdirSync(join(tmpDir, ".claude", "skills", "release"), {
        recursive: true,
      });
      mkdirSync(join(tmpDir, ".vscode"), { recursive: true });
      mkdirSync(join(tmpDir, "src"), { recursive: true });
      writeFileSync(
        join(tmpDir, "package.json"),
        JSON.stringify(
          {
            dependencies: {
              "left-pad": "1.3.0",
            },
            name: "ai-inventory-demo",
            version: "1.0.0",
          },
          null,
          2,
        ),
      );
      writeFileSync(
        join(tmpDir, "package-lock.json"),
        JSON.stringify(
          {
            lockfileVersion: 3,
            name: "ai-inventory-demo",
            packages: {
              "": {
                dependencies: {
                  "left-pad": "1.3.0",
                },
                name: "ai-inventory-demo",
                version: "1.0.0",
              },
              "node_modules/left-pad": {
                resolved:
                  "https://registry.npmjs.org/left-pad/-/left-pad-1.3.0.tgz",
                version: "1.3.0",
              },
            },
            requires: true,
            version: "1.0.0",
          },
          null,
          2,
        ),
      );
      writeFileSync(
        join(tmpDir, "CLAUDE.md"),
        "Use the release skill before publishing artifacts.",
      );
      writeFileSync(
        join(tmpDir, ".claude", "skills", "release", "SKILL.md"),
        [
          "---",
          "name: release",
          "description: Prepare release artifacts",
          "---",
          "Use this skill before shipping.",
        ].join("\n"),
      );
      writeFileSync(
        join(tmpDir, ".vscode", "mcp.json"),
        JSON.stringify(
          {
            mcpServers: {
              releaseDocs: {
                endpoint: "https://example.com/mcp",
                transport: "http",
              },
            },
          },
          null,
          2,
        ),
      );
      writeFileSync(
        join(tmpDir, "src", "index.ts"),
        [
          'import OpenAI from "openai";',
          'const model = "gpt-4o-mini";',
          'await fetch("https://api.openai.com/v1/responses");',
        ].join("\n"),
      );
      writeFileSync(
        join(tmpDir, "pyproject.toml"),
        [
          "[project]",
          'name = "demo-python-app"',
          'version = "0.1.0"',
          'requires-python = ">=3.10"',
        ].join("\n"),
      );
      writeFileSync(
        join(tmpDir, "server.py"),
        [
          "import mcp.server.stdio",
          "import mcp.types as mtypes",
          "from mcp.server import Server",
          "",
          'server = Server("python-release-docs", version="0.2.0")',
          "",
          "@server.list_tools()",
          "async def handle_list_tools():",
          '    return [mtypes.Tool(name="summarize_vulns", description="Summarize vulns", inputSchema={"type": "object"})]',
          "",
          "async with mcp.server.stdio.stdio_server() as (read_stream, write_stream):",
          "    await server.run(read_stream, write_stream, None)",
        ].join("\n"),
      );
      try {
        const baseOptions = {
          installDeps: false,
          multiProject: false,
          specVersion: 1.7,
        };
        const jsOptions = {
          ...baseOptions,
          projectType: ["js"],
        };
        const jsBomJson = postProcess(
          await createBom(tmpDir, jsOptions),
          jsOptions,
          tmpDir,
        ).bomJson;
        assert.ok(
          !(jsBomJson.components || []).some((component) =>
            ["agent-instructions", "mcp-config", "skill-file"].includes(
              getProp(component, "cdx:file:kind"),
            ),
          ),
          "did not expect AI inventory components in js scan without opt-in",
        );
        assert.ok(
          !(jsBomJson.services || []).some((service) =>
            service.properties?.some((property) =>
              property.name.startsWith("cdx:mcp:"),
            ),
          ),
          "did not expect MCP services in js scan without opt-in",
        );

        const dockerOptions = {
          ...baseOptions,
          projectType: ["js", "docker"],
        };
        const dockerBomJson = postProcess(
          await createNodejsBom(tmpDir, dockerOptions),
          dockerOptions,
          tmpDir,
        ).bomJson;
        assert.ok(
          !(dockerBomJson.components || []).some((component) =>
            ["agent-instructions", "mcp-config", "skill-file"].includes(
              getProp(component, "cdx:file:kind"),
            ),
          ),
          "did not expect AI inventory components in docker js scan without opt-in",
        );

        const exactAiSkillOptions = {
          ...baseOptions,
          projectType: ["ai-skill"],
        };
        const aiSkillBomJson = postProcess(
          await createBom(tmpDir, exactAiSkillOptions),
          exactAiSkillOptions,
          tmpDir,
        ).bomJson;
        assert.ok(
          (aiSkillBomJson.components || []).some(
            (component) =>
              component.name === "CLAUDE.md" &&
              getProp(component, "cdx:file:kind") === "agent-instructions",
          ),
          "expected CLAUDE.md in exact ai-skill scan",
        );
        assert.ok(
          !(aiSkillBomJson.components || []).some(
            (component) => getProp(component, "cdx:file:kind") === "mcp-config",
          ),
          "did not expect MCP configs in exact ai-skill scan",
        );

        const directAiOptions = {
          ...baseOptions,
          projectType: ["ai"],
        };
        const directModelfile = join(tmpDir, "Modelfile");
        writeFileSync(
          directModelfile,
          [
            "FROM deepseek-ai/DeepSeek-R1-Distill-Qwen-7B",
            "PARAMETER num_ctx 65536",
          ].join("\n"),
        );
        const directModelfileBomJson = postProcess(
          await createBom(directModelfile, directAiOptions),
          directAiOptions,
          tmpDir,
        ).bomJson;
        assert.ok(
          (directModelfileBomJson.components || []).some(
            (component) =>
              component.purl ===
              "pkg:huggingface/deepseek-ai/DeepSeek-R1-Distill-Qwen-7B",
          ),
          "expected Hugging Face model component in direct Modelfile AI-BOM",
        );
        const directModelfileFindings = await auditBom(directModelfileBomJson, {
          bomAuditCategories: "ai-bom",
          bomAuditMinSeverity: "low",
        });
        assert.ok(Array.isArray(directModelfileFindings));

        const directGguf = join(tmpDir, "tinyllama.gguf");
        writeGgufFixture(directGguf);
        const directGgufBomJson = postProcess(
          await createBom(directGguf, directAiOptions),
          directAiOptions,
          tmpDir,
        ).bomJson;
        assert.ok(
          (directGgufBomJson.components || []).some(
            (component) =>
              component.name === "TinyLlama-1.1B" &&
              getProp(component, "cdx:ai:artifactFormat") === "gguf",
          ),
          "expected GGUF model component in direct GGUF AI-BOM",
        );
        const directGgufFindings = await auditBom(directGgufBomJson, {
          bomAuditCategories: "ai-bom",
          bomAuditMinSeverity: "low",
        });
        assert.ok(Array.isArray(directGgufFindings));

        const directHfDatasetPurl =
          "pkg:huggingface/rohitnagareddy/python-coding-instructions?repository_url=https:%2F%2Fhuggingface.co%2Fdatasets";
        const directHfDatasetResolvedBomRef =
          "pkg:huggingface/rohitnagareddy/python-coding-instructions@data123?repository_url=https:%2F%2Fhuggingface.co%2Fdatasets";
        const directHfModelPurl =
          "pkg:huggingface/rohitnagareddy/Qwen3-0.6B-Coding-Finetuned-v1@fixture-sha";
        const directHfModelRef =
          "pkg:huggingface/rohitnagareddy/Qwen3-0.6B-Coding-Finetuned-v1";
        const directHfSpacePurl =
          "pkg:huggingface/rohitnagareddy/qwen-coding-demo-space@space456?repository_url=https:%2F%2Fhuggingface.co%2Fspaces";
        const { cdxgenAgent } = await import("../ecosystems/utils.js");
        const fetchStub = sinon
          .stub(cdxgenAgent, "get")
          .callsFake(async (url) => {
            if (
              url.includes(
                "/api/datasets/rohitnagareddy/python-coding-instructions/revision/HEAD?",
              )
            ) {
              return {
                body: {
                  id: "rohitnagareddy/python-coding-instructions",
                  sha: "DATA123",
                  description: "Coding dataset fixture",
                  downloads: 321,
                  private: false,
                  tags: ["coding"],
                },
              };
            }
            if (
              url.includes(
                "/api/spaces/rohitnagareddy/qwen-coding-demo-space/revision/HEAD?",
              )
            ) {
              return {
                body: {
                  id: "rohitnagareddy/qwen-coding-demo-space",
                  sha: "SPACE456",
                  datasets: ["rohitnagareddy/python-coding-instructions"],
                  likes: 7,
                  models: ["rohitnagareddy/Qwen3-0.6B-Coding-Finetuned-v1"],
                  private: false,
                  runtime: {
                    stage: "RUNNING",
                  },
                  sdk: "gradio",
                  subdomain: "qwen-coding-demo-space",
                  tags: ["demo"],
                },
              };
            }
            return {
              body: {
                id: "rohitnagareddy/Qwen3-0.6B-Coding-Finetuned-v1",
                sha: "fixture-sha",
                license: "apache-2.0",
                pipeline_tag: "text-generation",
                cardData: {
                  base_model: "Qwen/Qwen3-0.6B",
                  base_model_relation: "finetune",
                  datasets: ["rohitnagareddy/python-coding-instructions"],
                  quantization: "GGUF Q4_K_M",
                },
                siblings: [{ rfilename: "LICENSE" }],
                tags: ["qwen3", "finetune"],
              },
            };
          });
        try {
          const directHfBomJson = postProcess(
            await createBom(
              "pkg:huggingface/rohitnagareddy/Qwen3-0.6B-Coding-Finetuned-v1",
              directAiOptions,
            ),
            directAiOptions,
            tmpDir,
          ).bomJson;
          const directHfComponent = (directHfBomJson.components || []).find(
            (component) => component?.purl === directHfModelPurl,
          );
          assert.ok(
            directHfComponent,
            "expected direct Hugging Face component",
          );
          assert.ok(
            directHfComponent.pedigree?.ancestors?.some((component) =>
              component?.purl?.startsWith("pkg:huggingface/Qwen/Qwen3-0.6B"),
            ),
          );
          assert.ok(
            directHfComponent.pedigree?.notes?.includes("fine-tuned"),
            "expected direct Hugging Face pedigree notes to record the detected fine-tuned variant",
          );
          assert.ok(
            (directHfBomJson.dependencies || []).some(
              (dependency) =>
                dependency.ref === directHfComponent["bom-ref"] &&
                dependency.dependsOn?.includes(directHfDatasetPurl),
            ),
            "expected direct Hugging Face BOM to link the encoded dataset purl dependency",
          );
          const directFindings = await auditBom(directHfBomJson, {
            bomAuditCategories: "ai-bom",
            bomAuditMinSeverity: "low",
          });
          assert.ok(Array.isArray(directFindings));

          const directHfUrlBomJson = postProcess(
            await createBom(
              "https://huggingface.co/rohitnagareddy/Qwen3-0.6B-Coding-Finetuned-v1",
              directAiOptions,
            ),
            directAiOptions,
            tmpDir,
          ).bomJson;
          assert.ok(
            (directHfUrlBomJson.components || []).some(
              (component) => component?.purl === directHfModelPurl,
            ),
            "expected direct Hugging Face URL component",
          );
          const directUrlFindings = await auditBom(directHfUrlBomJson, {
            bomAuditCategories: "ai-bom",
            bomAuditMinSeverity: "low",
          });
          assert.ok(Array.isArray(directUrlFindings));

          const directHfDatasetBomJson = postProcess(
            await createBom(
              "https://huggingface.co/datasets/rohitnagareddy/python-coding-instructions",
              directAiOptions,
            ),
            directAiOptions,
            tmpDir,
          ).bomJson;
          assert.ok(
            (directHfDatasetBomJson.components || []).some(
              (component) =>
                component?.type === "data" &&
                component?.["bom-ref"] === directHfDatasetResolvedBomRef,
            ),
            "expected direct Hugging Face dataset URL component with the resolved encoded dataset bom-ref",
          );

          const directHfSpaceBomJson = postProcess(
            await createBom(
              "https://huggingface.co/spaces/rohitnagareddy/qwen-coding-demo-space",
              directAiOptions,
            ),
            directAiOptions,
            tmpDir,
          ).bomJson;
          assert.ok(
            (directHfSpaceBomJson.components || []).some(
              (component) =>
                component?.type === "application" &&
                component?.purl === directHfSpacePurl,
            ),
            "expected direct Hugging Face Space URL component with encoded repository_url qualifier",
          );
          assert.ok(
            (directHfSpaceBomJson.dependencies || []).some(
              (dependency) =>
                dependency.ref === directHfSpacePurl &&
                dependency.dependsOn?.includes(directHfDatasetPurl) &&
                dependency.dependsOn?.includes(directHfModelRef),
            ),
            "expected direct Hugging Face Space BOM to keep dataset and model dependency refs",
          );
        } finally {
          fetchStub.restore();
        }

        const optedInJsOptions = {
          ...baseOptions,
          projectType: ["js", "ai-skill", "mcp"],
        };
        const optedInJsBomJson = postProcess(
          await createBom(tmpDir, optedInJsOptions),
          optedInJsOptions,
          tmpDir,
        ).bomJson;
        assert.ok(
          (optedInJsBomJson.components || []).some(
            (component) =>
              getProp(component, "cdx:file:kind") === "skill-file" &&
              getProp(component, "cdx:skill:name") === "release",
          ),
          "expected skill file in opted-in js scan",
        );
        assert.ok(
          (optedInJsBomJson.components || []).some(
            (component) => getProp(component, "cdx:file:kind") === "mcp-config",
          ),
          "expected MCP config in opted-in js scan",
        );
        assert.ok(
          (optedInJsBomJson.services || []).some(
            (service) =>
              service.name === "releaseDocs" &&
              getProp(service, "cdx:mcp:inventorySource") === "config-file",
          ),
          "expected MCP config service in opted-in js scan",
        );

        const auditAliasJsOptions = {
          ...baseOptions,
          bomAuditCategories: "ai-inventory",
          projectType: ["js"],
        };
        const auditAliasJsBomJson = postProcess(
          await createBom(tmpDir, auditAliasJsOptions),
          auditAliasJsOptions,
          tmpDir,
        ).bomJson;
        assert.ok(
          (auditAliasJsBomJson.components || []).some(
            (component) =>
              getProp(component, "cdx:file:kind") === "skill-file" &&
              getProp(component, "cdx:skill:name") === "release",
          ),
          "expected skill file in ai-inventory audit-category js scan",
        );
        assert.ok(
          (auditAliasJsBomJson.components || []).some(
            (component) => getProp(component, "cdx:file:kind") === "mcp-config",
          ),
          "expected MCP config in ai-inventory audit-category js scan",
        );
        assert.ok(
          (auditAliasJsBomJson.services || []).some(
            (service) =>
              service.name === "releaseDocs" &&
              getProp(service, "cdx:mcp:inventorySource") === "config-file",
          ),
          "expected MCP config service in ai-inventory audit-category js scan",
        );
        assert.ok(
          (auditAliasJsBomJson.components || []).some(
            (component) =>
              component.type === "machine-learning-model" &&
              component.name === "gpt-4o-mini" &&
              getProp(component, "cdx:ai:provider") === "openai",
          ),
          "expected AI model component in ai-inventory audit-category js scan",
        );
        assert.ok(
          (auditAliasJsBomJson.services || []).some(
            (service) =>
              service.group === "openai" &&
              getProp(service, "cdx:ai:modelId") === "gpt-4o-mini",
          ),
          "expected AI provider service in ai-inventory audit-category js scan",
        );

        const auditAgentJsOptions = {
          ...baseOptions,
          bomAuditCategories: "ai-agent",
          projectType: ["js"],
        };
        const auditAgentJsBomJson = postProcess(
          await createBom(tmpDir, auditAgentJsOptions),
          auditAgentJsOptions,
          tmpDir,
        ).bomJson;
        assert.ok(
          (auditAgentJsBomJson.components || []).some(
            (component) =>
              getProp(component, "cdx:file:kind") === "skill-file" &&
              getProp(component, "cdx:skill:name") === "release",
          ),
          "expected skill file in ai-agent audit-category js scan",
        );
        assert.ok(
          !(auditAgentJsBomJson.components || []).some(
            (component) => getProp(component, "cdx:file:kind") === "mcp-config",
          ),
          "did not expect MCP config in ai-agent audit-category js scan",
        );
        assert.ok(
          (auditAgentJsBomJson.components || []).some(
            (component) =>
              component.type === "machine-learning-model" &&
              component.name === "gpt-4o-mini",
          ),
          "expected AI model component in ai-agent audit-category js scan",
        );

        const filteredOptions = {
          ...baseOptions,
          excludeType: ["ai-skill", "mcp"],
          projectType: ["js", "ai-skill", "mcp"],
        };
        const filteredBomJson = postProcess(
          await createBom(tmpDir, filteredOptions),
          filteredOptions,
          tmpDir,
        ).bomJson;
        assert.ok(
          !(filteredBomJson.components || []).some((component) =>
            ["agent-instructions", "mcp-config", "skill-file"].includes(
              getProp(component, "cdx:file:kind"),
            ),
          ),
          "did not expect AI inventory components after exclude-type filtering",
        );
        assert.ok(
          !(filteredBomJson.services || []).some((service) =>
            service.properties?.some((property) =>
              property.name.startsWith("cdx:mcp:"),
            ),
          ),
          "did not expect MCP services after exclude-type filtering",
        );

        const pyOptions = {
          ...baseOptions,
          projectType: ["py"],
        };
        const pyBomJson = postProcess(
          await createBom(tmpDir, pyOptions),
          pyOptions,
          tmpDir,
        ).bomJson;
        assert.ok(
          !(pyBomJson.components || []).some((component) =>
            ["agent-instructions", "mcp-config", "skill-file"].includes(
              getProp(component, "cdx:file:kind"),
            ),
          ),
          "did not expect AI inventory components in python scan without opt-in",
        );
        assert.ok(
          !(pyBomJson.services || []).some((service) =>
            service.properties?.some((property) =>
              property.name.startsWith("cdx:mcp:"),
            ),
          ),
          "did not expect MCP services in python scan without opt-in",
        );

        const optedInPyOptions = {
          ...baseOptions,
          projectType: ["py", "ai-skill", "mcp"],
        };
        const optedInPyBomJson = postProcess(
          await createPythonBom(tmpDir, optedInPyOptions),
          optedInPyOptions,
          tmpDir,
        ).bomJson;
        assert.ok(
          (optedInPyBomJson.components || []).some(
            (component) =>
              getProp(component, "cdx:file:kind") === "skill-file" &&
              getProp(component, "cdx:skill:name") === "release",
          ),
          "expected skill file in opted-in python scan",
        );
        assert.ok(
          (optedInPyBomJson.components || []).some(
            (component) => getProp(component, "cdx:file:kind") === "mcp-config",
          ),
          "expected MCP config in opted-in python scan",
        );
        assert.ok(
          (optedInPyBomJson.services || []).some(
            (service) =>
              service.name === "python-release-docs" &&
              getProp(service, "cdx:mcp:inventorySource") ===
                "source-code-analysis",
          ),
          "expected Python MCP service in opted-in python scan",
        );

        const auditMcpPyOptions = {
          ...baseOptions,
          bomAuditCategories: "mcp-server",
          projectType: ["py"],
        };
        const auditMcpPyBomJson = postProcess(
          await createPythonBom(tmpDir, auditMcpPyOptions),
          auditMcpPyOptions,
          tmpDir,
        ).bomJson;
        assert.ok(
          (auditMcpPyBomJson.services || []).some(
            (service) =>
              service.name === "python-release-docs" &&
              getProp(service, "cdx:mcp:inventorySource") ===
                "source-code-analysis",
          ),
          "expected Python MCP service in mcp-server audit-category scan",
        );
        assert.ok(
          !(auditMcpPyBomJson.components || []).some(
            (component) => getProp(component, "cdx:file:kind") === "skill-file",
          ),
          "did not expect skill file in mcp-server audit-category python scan",
        );
      } finally {
        rmSync(tmpDir, { force: true, recursive: true });
      }
    });

    it("does not trace an npm registry config read when opening .npmrc fails", async () => {
      const tmpDir = mkdtempSync(join(tmpdir(), "cdxgen-npmrc-read-fail-"));
      writeFileSync(
        join(tmpDir, "package.json"),
        JSON.stringify({
          name: "npmrc-read-fail",
          version: "1.0.0",
        }),
      );
      mkdirSync(join(tmpDir, ".npmrc"), { recursive: true });
      setDryRunMode(true);
      resetRecordedActivities();
      try {
        await assert.rejects(() =>
          createNodejsBom(tmpDir, {
            installDeps: true,
            multiProject: false,
            projectType: ["npm"],
          }),
        );
        const readActivities = getRecordedActivities().filter(
          (activity) =>
            activity.kind === "read" &&
            activity.target === join(tmpDir, ".npmrc"),
        );
        assert.deepStrictEqual(readActivities, []);
      } finally {
        setDryRunMode(false);
        resetRecordedActivities();
        rmSync(tmpDir, { force: true, recursive: true });
      }
    });
  });

  describe("createCsharpBom() multi-project manifests", () => {
    const dataDir = join(
      dirname(fileURLToPath(import.meta.url)),
      "..",
      "..",
      "test",
      "data",
    );

    it("does not drop packages.config when a sibling project has project.assets.json", async () => {
      // Regression test for SIQ-290: in a multi-project scan, a modern
      // project.assets.json / packages.lock.json in one project used to cause
      // packages.config dependencies of unrelated projects to be dropped.
      const tempDir = mkdtempSync(join(tmpdir(), "cdxgen-dotnet-multiproj-"));
      try {
        const legacyDir = join(tempDir, "LegacyProj");
        const modernObjDir = join(tempDir, "ModernProj", "obj");
        mkdirSync(legacyDir, { recursive: true });
        mkdirSync(modernObjDir, { recursive: true });
        copyFileSync(
          join(dataDir, "packages.config"),
          join(legacyDir, "packages.config"),
        );
        copyFileSync(
          join(dataDir, "project.assets.json"),
          join(modernObjDir, "project.assets.json"),
        );

        const bomNSData = await createCsharpBom(tempDir, {
          multiProject: true,
          projectType: ["dotnet"],
        });
        const componentNames = (bomNSData.bomJson.components || []).map(
          (c) => c.name,
        );
        // From LegacyProj/packages.config
        assert.ok(
          componentNames.includes("Antlr"),
          "packages.config dependencies should be retained",
        );
        assert.ok(
          componentNames.includes("EntityFramework"),
          "packages.config dependencies should be retained",
        );
        // From ModernProj/obj/project.assets.json
        assert.ok(
          componentNames.includes("log4net"),
          "project.assets.json dependencies should be retained",
        );
      } finally {
        rmSync(tempDir, { force: true, recursive: true });
      }
    });

    it("does not double-count packages.config when the same project has a modern manifest", async () => {
      // When a single project directory has both packages.config and a
      // project.assets.json, the modern manifest takes precedence and the
      // packages.config is skipped for that project.
      const tempDir = mkdtempSync(join(tmpdir(), "cdxgen-dotnet-sameproj-"));
      try {
        const projDir = join(tempDir, "Proj");
        const objDir = join(projDir, "obj");
        mkdirSync(objDir, { recursive: true });
        copyFileSync(
          join(dataDir, "packages.config"),
          join(projDir, "packages.config"),
        );
        copyFileSync(
          join(dataDir, "project.assets.json"),
          join(objDir, "project.assets.json"),
        );

        const bomNSData = await createCsharpBom(tempDir, {
          multiProject: true,
          projectType: ["dotnet"],
        });
        const componentNames = (bomNSData.bomJson.components || []).map(
          (c) => c.name,
        );
        // packages.config-only package must NOT appear since assets supersede it
        assert.ok(
          !componentNames.includes("Antlr"),
          "packages.config should be skipped when project.assets.json covers the same project",
        );
        assert.ok(
          componentNames.includes("log4net"),
          "project.assets.json dependencies should be retained",
        );
      } finally {
        rmSync(tempDir, { force: true, recursive: true });
      }
    });

    const mixedDataDir = join(dataDir, "csharp-mixed-manifests");
    // evidence.identity is an object for a single manifest and an array once
    // trimComponents merges evidence from multiple manifests
    const identityList = (comp) => {
      const identity = comp?.evidence?.identity;
      if (!identity) {
        return [];
      }
      return Array.isArray(identity) ? identity : [identity];
    };

    it("tracks both versions when packages.config and packages.lock.json disagree", async () => {
      const bomNSData = await createCsharpBom(
        join(mixedDataDir, "DiffVersion"),
        {
          multiProject: true,
          projectType: ["dotnet"],
          specVersion: 1.7,
        },
      );
      const components = bomNSData.bomJson.components || [];
      const njVersions = components
        .filter((c) => c.name === "Newtonsoft.Json")
        .map((c) => c.version)
        .sort();
      assert.deepStrictEqual(
        njVersions,
        ["12.0.3", "13.0.3"],
        "both the packages.config and the packages.lock.json versions must be tracked",
      );
      assert.ok(
        components.some(
          (c) => c.name === "EntityFramework" && c.version === "6.4.4",
        ),
        "packages.config-only dependencies must be retained",
      );
      // Each version must stay attributable to the manifest it came from
      const legacyNj = components.find(
        (c) => c.name === "Newtonsoft.Json" && c.version === "12.0.3",
      );
      const legacyIdentities = identityList(legacyNj);
      assert.deepStrictEqual(legacyIdentities[0].confidence, 0.7);
      assert.ok(
        legacyIdentities[0].methods[0].value.endsWith("packages.config"),
        "the packages.config version must carry packages.config evidence",
      );
      const modernNj = components.find(
        (c) => c.name === "Newtonsoft.Json" && c.version === "13.0.3",
      );
      const modernIdentities = identityList(modernNj);
      assert.deepStrictEqual(modernIdentities[0].confidence, 1);
      assert.ok(
        modernIdentities[0].methods[0].value.endsWith("packages.lock.json"),
        "the packages.lock.json version must carry packages.lock.json evidence",
      );
    });

    it("merges properties and evidence when packages.config and packages.lock.json agree", async () => {
      const bomNSData = await createCsharpBom(
        join(mixedDataDir, "SameVersion"),
        {
          multiProject: true,
          projectType: ["dotnet"],
          specVersion: 1.7,
        },
      );
      const components = (bomNSData.bomJson.components || []).filter(
        (c) => c.name === "Newtonsoft.Json",
      );
      assert.deepStrictEqual(
        components.length,
        1,
        "same package and version from two manifests must merge into one component",
      );
      const srcFiles = (components[0].properties || [])
        .filter((p) => p.name === "internal:SrcFile")
        .map((p) => p.value);
      assert.ok(
        srcFiles.some((v) => v.endsWith("packages.lock.json")),
        "SrcFile property from packages.lock.json must be retained",
      );
      assert.ok(
        srcFiles.some((v) => v.endsWith("packages.config")),
        "SrcFile property from packages.config must be retained",
      );
      const identities = identityList(components[0]);
      const methodValues = identities
        .flatMap((i) => i.methods || [])
        .map((m) => m.value);
      assert.ok(
        methodValues.some((v) => v.endsWith("packages.lock.json")),
        "evidence from packages.lock.json must be retained",
      );
      assert.ok(
        methodValues.some((v) => v.endsWith("packages.config")),
        "evidence from packages.config must be retained",
      );
      // Merging the lower-confidence packages.config evidence must not
      // degrade the confidence established by the lock file
      assert.deepStrictEqual(identities.length, 1);
      assert.deepStrictEqual(
        identities[0].confidence,
        1,
        "merged identity must retain the highest confidence",
      );
    });

    it("lowers the confidence for imprecise packages.config versions", async () => {
      const bomNSData = await createCsharpBom(
        join(mixedDataDir, "ImpreciseVersions"),
        {
          multiProject: true,
          projectType: ["dotnet"],
          specVersion: 1.7,
        },
      );
      const components = bomNSData.bomJson.components || [];
      const confidenceFor = (name) => {
        const comp = components.find((c) => c.name === name);
        assert.ok(comp, `component ${name} must be present`);
        const identities = identityList(comp);
        assert.ok(identities.length, `component ${name} must carry evidence`);
        return identities[0].confidence;
      };
      assert.deepStrictEqual(
        confidenceFor("Antlr"),
        0.7,
        "exact versions keep the regular manifest confidence",
      );
      assert.deepStrictEqual(
        confidenceFor("Moq"),
        0.7,
        "prerelease versions are precise",
      );
      assert.deepStrictEqual(
        confidenceFor("Castle.Core"),
        0.7,
        "exact-pin ranges such as [4.4.1] are precise",
      );
      assert.deepStrictEqual(
        confidenceFor("NUnit"),
        0.5,
        "range versions must get a lower confidence",
      );
      assert.deepStrictEqual(
        confidenceFor("log4net"),
        0.5,
        "wildcard versions must get a lower confidence",
      );
      assert.deepStrictEqual(
        confidenceFor("jQuery"),
        0.5,
        "bare wildcard versions must get a lower confidence",
      );
      // Packages without a resolvable version must still be tracked
      for (const name of [
        "Newtonsoft.Json",
        "Serilog",
        "WebGrease",
        "bootstrap",
      ]) {
        assert.ok(
          components.some((c) => c.name === name),
          `${name} must be tracked even without a precise version`,
        );
      }
      assert.ok(
        !components.some((c) => c.purl?.includes("$(")),
        "templated versions must not leak into purls",
      );
      assert.ok(
        !components.some(
          (c) => c.purl?.includes("@undefined") || c.purl?.endsWith("@"),
        ),
        "missing versions must not produce bogus purls",
      );
    });

    it("backfills templated packages.config versions from resolved manifests", async () => {
      const bomNSData = await createCsharpBom(
        join(mixedDataDir, "TemplatedBackfill"),
        {
          multiProject: true,
          projectType: ["dotnet"],
          specVersion: 1.7,
        },
      );
      const components = (bomNSData.bomJson.components || []).filter(
        (c) => c.name === "Newtonsoft.Json",
      );
      assert.deepStrictEqual(
        components.length,
        1,
        "backfilled packages.config component must merge with the packages.lock.json component",
      );
      assert.deepStrictEqual(components[0].version, "13.0.3");
      const identities = identityList(components[0]);
      const methodValues = identities
        .flatMap((i) => i.methods || [])
        .map((m) => m.value);
      assert.ok(
        methodValues.some((v) => v.endsWith("packages.config")),
        "evidence from packages.config must be retained after backfill",
      );
      assert.deepStrictEqual(
        identities[0].confidence,
        1,
        "the lock file confidence must win over the backfilled evidence",
      );
    });

    it("resolves versions from a Directory.Packages.props above the scanned directory", async () => {
      // The user in #4303 pointed cdxgen at ./src while Directory.Packages.props sat
      // at the repository root, so the props file is deliberately outside the scan.
      const bomNSData = await createCsharpBom(
        join(mixedDataDir, "CentralPackageManagement", "src"),
        {
          multiProject: true,
          projectType: ["dotnet"],
          specVersion: 1.7,
        },
      );
      const byName = {};
      for (const c of bomNSData.bomJson.components || []) {
        byName[c.name] = c;
      }
      assert.deepStrictEqual(byName.WiX.version, "3.14.1");
      assert.deepStrictEqual(byName.WiX.purl, "pkg:nuget/WiX@3.14.1");
      assert.deepStrictEqual(byName.Serilog.version, "3.1.1");
      assert.deepStrictEqual(byName["Newtonsoft.Json"].version, "13.0.3");
      assert.deepStrictEqual(byName.Moq.version, "4.18.4");
      assert.ok(
        byName["Unlisted.Package"],
        "a package with no central version must still be tracked",
      );
      assert.ok(
        !(bomNSData.bomJson.components || []).some(
          (c) => c.purl?.includes("@undefined") || c.purl?.endsWith("@"),
        ),
        "missing versions must not produce bogus purls",
      );
    });

    it("builds a complete dependency graph across legacy and modern manifests", async () => {
      const bomNSData = await createCsharpBom(join(mixedDataDir, "DepGraph"), {
        multiProject: true,
        projectType: ["dotnet"],
        specVersion: 1.7,
      });
      const componentNames = (bomNSData.bomJson.components || []).map(
        (c) => c.name,
      );
      for (const name of ["EntityFramework", "Serilog.Sinks.File", "Serilog"]) {
        assert.ok(
          componentNames.includes(name),
          `component ${name} must be present`,
        );
      }
      const dependencies = bomNSData.bomJson.dependencies || [];
      const parentRef = bomNSData.bomJson.metadata.component["bom-ref"];
      const parentEntry = dependencies.find((d) => d.ref === parentRef);
      assert.ok(
        parentEntry,
        "the parent component must have a dependency entry",
      );
      assert.ok(
        parentEntry.dependsOn.includes("pkg:nuget/EntityFramework@6.4.4"),
        "packages.config dependencies must be attached to the parent",
      );
      assert.ok(
        parentEntry.dependsOn.includes("pkg:nuget/Serilog.Sinks.File@5.0.0"),
        "direct packages.lock.json dependencies must be attached to the parent",
      );
      const sinksEntry = dependencies.find(
        (d) => d.ref === "pkg:nuget/Serilog.Sinks.File@5.0.0",
      );
      assert.ok(
        sinksEntry,
        "packages.lock.json components must have dependency entries",
      );
      assert.deepStrictEqual(
        sinksEntry.dependsOn,
        ["pkg:nuget/Serilog@2.10.0"],
        "transitive edges from packages.lock.json must be preserved",
      );
    });
  });
  describe("createCryptoCertsBom() dosai crypto analysis", () => {
    it("does not invoke dosai crypto analysis for non-.NET CBOM scans", async () => {
      const tempDir = mkdtempSync(join(tmpdir(), "cdxgen-cbom-non-dotnet-"));
      const collectDosaiCryptoComponents = sinon.stub().resolves([]);
      try {
        const { createCryptoCertsBom } = await esmock("./managedBom.js", {
          "../inventory/cbomutils.js": {
            collectDosaiCryptoComponents,
            collectSourceCryptoComponents: sinon.stub().resolves([]),
          },
        });

        await createCryptoCertsBom(tempDir, {
          projectType: ["js"],
          specVersion: 1.7,
        });

        sinon.assert.notCalled(collectDosaiCryptoComponents);
      } finally {
        rmSync(tempDir, { force: true, recursive: true });
      }
    });

    it("invokes dosai crypto analysis for explicit .NET CBOM scans", async () => {
      const tempDir = mkdtempSync(join(tmpdir(), "cdxgen-cbom-dotnet-"));
      const collectDosaiCryptoComponents = sinon.stub().resolves([
        {
          name: "sha-256",
          type: "cryptographic-asset",
          "bom-ref": "crypto/algorithm/sha-256@2.16.840.1.101.3.4.2.1",
          cryptoProperties: {
            assetType: "algorithm",
            oid: "2.16.840.1.101.3.4.2.1",
          },
        },
      ]);
      try {
        const { createCryptoCertsBom } = await esmock("./managedBom.js", {
          "../inventory/cbomutils.js": {
            collectDosaiCryptoComponents,
            collectSourceCryptoComponents: sinon.stub().resolves([]),
          },
        });

        const bomData = await createCryptoCertsBom(tempDir, {
          projectType: ["dotnet"],
          specVersion: 1.7,
        });

        sinon.assert.calledOnce(collectDosaiCryptoComponents);
        assert.strictEqual(bomData.bomJson.components[0].name, "sha-256");
      } finally {
        rmSync(tempDir, { force: true, recursive: true });
      }
    });

    it("invokes dosai crypto analysis when universal scans contain .NET project files", async () => {
      const tempDir = mkdtempSync(
        join(tmpdir(), "cdxgen-cbom-dotnet-indicator-"),
      );
      const collectDosaiCryptoComponents = sinon.stub().resolves([]);
      try {
        writeFileSync(join(tempDir, "app.csproj"), "<Project />");
        const { createCryptoCertsBom } = await esmock("./managedBom.js", {
          "../inventory/cbomutils.js": {
            collectDosaiCryptoComponents,
            collectSourceCryptoComponents: sinon.stub().resolves([]),
          },
        });

        await createCryptoCertsBom(tempDir, {
          projectType: ["universal"],
          specVersion: 1.7,
        });

        sinon.assert.calledOnce(collectDosaiCryptoComponents);
      } finally {
        rmSync(tempDir, { force: true, recursive: true });
      }
    });
  });

  describe("createPythonBom() lock file root dependencies", () => {
    const expectedDirectDeps = [
      "pkg:pypi/certifi@2022.12.7",
      "pkg:pypi/charset-normalizer@2.0.12",
      "pkg:pypi/idna@3.3",
      "pkg:pypi/requests@2.28.0",
      "pkg:pypi/urllib3@1.26.13",
    ];

    for (const [lockName, fixtureDirPath] of [
      ["uv.lock", uvSmokeFixtureDir],
      ["pylock.toml", pyLockSmokeFixtureDir],
    ]) {
      it(`makes the parent component depend on the first level from ${lockName}`, async () => {
        const options = { installDeps: false, projectType: ["python"] };
        const bomJson = (await createPythonBom(fixtureDirPath, options))
          .bomJson;
        const parentRef = bomJson.metadata.component["bom-ref"];
        assert.strictEqual(parentRef, "pkg:pypi/uv-smoke@1.0.0");
        const parentEntry = bomJson.dependencies.find(
          (adep) => adep.ref === parentRef,
        );
        assert.ok(
          parentEntry,
          `expected a dependencies entry for ${parentRef}`,
        );
        assert.deepStrictEqual(parentEntry.dependsOn, expectedDirectDeps);
        assert.strictEqual(
          bomJson.dependencies.filter((adep) => adep.ref === parentRef).length,
          1,
          "expected a single entry for the parent component",
        );
      });
    }
  });
});
