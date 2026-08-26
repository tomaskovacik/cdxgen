import { assert, describe, it } from "poku";

import {
  buildDependencyTrackBomPayload,
  getDependencyTrackBomApiUrl,
  getDependencyTrackBomUrl,
} from "./dependency-track.js";

function partsOf(formData) {
  return formData.getBuffer().toString("utf8");
}

function fieldValue(formData, name) {
  const raw = partsOf(formData);
  const match = raw.match(
    new RegExp(`name="${name}"\\r\\n\\r\\n([\\s\\S]*?)\\r\\n--`),
  );
  return match?.[1];
}

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

  it("returns undefined when BOM contents are missing", () => {
    assert.strictEqual(
      buildDependencyTrackBomPayload({ projectName: "child" }, undefined),
      undefined,
    );
    assert.strictEqual(
      buildDependencyTrackBomPayload({ projectName: "child" }, null),
      undefined,
    );
  });

  it("builds a multipart/form-data payload with parentUUID and tags", () => {
    const payload = buildDependencyTrackBomPayload(
      {
        parentProjectId: "d9628844-5f04-4ca7-88a2-64eb6bc64db0",
        projectName: "child",
        projectTag: ["tag1", "tag2"],
        projectVersion: "1.0.0",
      },
      { bom: "test" },
    );
    assert.ok(payload, "payload should be defined");
    assert.match(
      payload.getHeaders()["content-type"],
      /^multipart\/form-data; boundary=/,
    );
    const raw = partsOf(payload);
    assert.match(raw, /name="bom"; filename="bom\.json"/);
    assert.match(raw, /\{"bom":"test"\}/);
    assert.strictEqual(fieldValue(payload, "autoCreate"), "true");
    assert.strictEqual(fieldValue(payload, "projectName"), "child");
    assert.strictEqual(fieldValue(payload, "projectVersion"), "1.0.0");
    assert.strictEqual(
      fieldValue(payload, "parentUUID"),
      "d9628844-5f04-4ca7-88a2-64eb6bc64db0",
    );
    assert.strictEqual(
      fieldValue(payload, "projectTags"),
      '[{"name":"tag1"},{"name":"tag2"}]',
    );
  });

  it("builds payload with parentName and parentVersion", () => {
    const payload = buildDependencyTrackBomPayload(
      {
        parentProjectName: "parent",
        parentProjectVersion: "2.0.0",
        projectName: "child",
        projectVersion: "1.0.0",
      },
      { bom: "test2" },
    );
    assert.strictEqual(fieldValue(payload, "parentName"), "parent");
    assert.strictEqual(fieldValue(payload, "parentVersion"), "2.0.0");
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
    assert.strictEqual(fieldValue(payload, "autoCreate"), "false");
    assert.strictEqual(fieldValue(payload, "isLatest"), "true");
    assert.strictEqual(fieldValue(payload, "projectVersion"), "main");
  });

  it("defaults projectVersion to main when only projectName is provided", () => {
    const payload = buildDependencyTrackBomPayload(
      { projectName: "child" },
      { bom: "test5" },
    );
    assert.strictEqual(fieldValue(payload, "projectVersion"), "main");
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
