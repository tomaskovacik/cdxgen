import { Buffer } from "node:buffer";
import { gunzipSync } from "node:zlib";

import { assert, describe, it } from "poku";

import {
  buildDependencyTrackBomPayload,
  getDependencyTrackBomApiUrl,
  getDependencyTrackBomUrl,
} from "./dependency-track.js";

describe("Dependency-Track helper tests", () => {
  it("returns submission URL without trailing slash duplication", () => {
    assert.strictEqual(
      getDependencyTrackBomUrl("https://dtrack.example.com/"),
      "https://dtrack.example.com/api/v1/bom",
    );
    assert.strictEqual(
      getDependencyTrackBomUrl("https://dtrack.example.com"),
      "https://dtrack.example.com/api/v1/bom",
    );
  });

  it("removes credentials, query strings, and fragments from the submission URL", () => {
    assert.strictEqual(
      getDependencyTrackBomUrl(
        "https://user:pass@dtrack.example.com/base/?token=secret#frag",
      ),
      "https://dtrack.example.com/base/api/v1/bom",
    );
  });

  it("returns a sanitized URL object for Dependency-Track requests", () => {
    const apiUrl = getDependencyTrackBomApiUrl(
      "https://user:pass@dtrack.example.com/base/?token=secret#frag",
    );
    assert.ok(apiUrl instanceof URL);
    assert.strictEqual(apiUrl?.hostname, "dtrack.example.com");
    assert.strictEqual(apiUrl?.pathname, "/base/api/v1/bom");
    assert.strictEqual(apiUrl?.username, "");
    assert.strictEqual(apiUrl?.password, "");
    assert.strictEqual(apiUrl?.search, "");
    assert.strictEqual(apiUrl?.hash, "");
  });

  it("rejects malformed or unsupported submission URLs", () => {
    assert.strictEqual(
      getDependencyTrackBomUrl("file:///tmp/dtrack"),
      undefined,
    );
    assert.strictEqual(
      getDependencyTrackBomApiUrl("file:///tmp/dtrack"),
      undefined,
    );
    assert.strictEqual(
      getDependencyTrackBomUrl("javascript:alert(1)"),
      undefined,
    );
    assert.strictEqual(
      getDependencyTrackBomApiUrl("javascript:alert(1)"),
      undefined,
    );
    assert.strictEqual(getDependencyTrackBomUrl("not a url"), undefined);
    assert.strictEqual(getDependencyTrackBomApiUrl("not a url"), undefined);
  });

  it("builds payload with parentUUID and tags", () => {
    const payload = buildDependencyTrackBomPayload(
      {
        projectName: "child",
        projectVersion: "1.0.0",
        parentProjectId: "d9628844-5f04-4ca7-88a2-64eb6bc64db0",
        projectTag: ["tag1", "tag2"],
      },
      { bom: "test" },
    );
    assert.deepStrictEqual(payload, {
      autoCreate: "true",
      bom: "eyJib20iOiJ0ZXN0In0=",
      parentUUID: "d9628844-5f04-4ca7-88a2-64eb6bc64db0",
      projectName: "child",
      projectTags: [{ name: "tag1" }, { name: "tag2" }],
      projectVersion: "1.0.0",
    });
  });

  it("builds payload with parentName and parentVersion", () => {
    const payload = buildDependencyTrackBomPayload(
      {
        projectName: "child",
        projectVersion: "1.0.0",
        parentProjectName: "parent",
        parentProjectVersion: "2.0.0",
      },
      { bom: "test2" },
    );
    assert.deepStrictEqual(payload, {
      autoCreate: "true",
      bom: "eyJib20iOiJ0ZXN0MiJ9",
      parentName: "parent",
      parentVersion: "2.0.0",
      projectName: "child",
      projectVersion: "1.0.0",
    });
  });

  it("returns undefined when project identity is missing", () => {
    const payload = buildDependencyTrackBomPayload({}, { bom: "test3" });
    assert.strictEqual(payload, undefined);
  });

  it("supports configurable autoCreate and isLatest", () => {
    const payload = buildDependencyTrackBomPayload(
      {
        autoCreate: false,
        isLatest: true,
        projectName: "child",
      },
      { bom: "test4" },
    );
    assert.deepStrictEqual(payload, {
      autoCreate: "false",
      bom: "eyJib20iOiJ0ZXN0NCJ9",
      isLatest: true,
      projectName: "child",
      projectVersion: "main",
    });
  });

  it("defaults projectVersion to main when only projectName is provided", () => {
    const payload = buildDependencyTrackBomPayload(
      { projectName: "child" },
      { bom: "test5" },
    );
    assert.deepStrictEqual(payload, {
      autoCreate: "true",
      bom: "eyJib20iOiJ0ZXN0NSJ9",
      projectName: "child",
      projectVersion: "main",
    });
  });

  it("compresses the BOM with gzip when dtCompressBom is true", () => {
    const bomContents = { bom: "compressed-test" };
    const payload = buildDependencyTrackBomPayload(
      { projectName: "child", dtCompressBom: true },
      bomContents,
    );
    assert.ok(payload, "payload should be defined");
    const decoded = Buffer.from(payload.bom, "base64");
    // gzip magic bytes: 0x1f 0x8b
    assert.strictEqual(decoded[0], 0x1f);
    assert.strictEqual(decoded[1], 0x8b);
    const decompressed = JSON.parse(gunzipSync(decoded).toString("utf8"));
    assert.deepStrictEqual(decompressed, bomContents);
    assert.strictEqual(payload.projectName, "child");
    assert.strictEqual(payload.projectVersion, "main");
  });

  it("does not compress the BOM when dtCompressBom is false or not set", () => {
    const bomContents = { bom: "plain-test" };
    const payload = buildDependencyTrackBomPayload(
      { projectName: "child", dtCompressBom: false },
      bomContents,
    );
    assert.ok(payload, "payload should be defined");
    const decoded = JSON.parse(
      Buffer.from(payload.bom, "base64").toString("utf8"),
    );
    assert.deepStrictEqual(decoded, bomContents);
  });

  it("returns undefined when parent UUID and parent name/version are both provided", () => {
    const payload = buildDependencyTrackBomPayload(
      {
        parentProjectId: "d9628844-5f04-4ca7-88a2-64eb6bc64db0",
        parentProjectName: "parent",
        parentProjectVersion: "1.0.0",
        projectName: "child",
      },
      { bom: "test6" },
    );
    assert.strictEqual(payload, undefined);
  });

  it("returns undefined when parent name/version mode is incomplete", () => {
    const payload = buildDependencyTrackBomPayload(
      {
        parentProjectName: "parent",
        projectName: "child",
      },
      { bom: "test7" },
    );
    assert.strictEqual(payload, undefined);
  });
});
