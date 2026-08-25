import { Buffer } from "node:buffer";
import { randomBytes } from "node:crypto";

import { hasDangerousUnicode } from "../../core/activity.js";

/**
 * Minimal multipart/form-data encoder covering the subset of the `form-data`
 * package's API this module needs (`append`, `getBuffer`, `getHeaders`).
 * Avoids taking on the `form-data` dependency for a handful of text fields
 * plus a single in-memory file part.
 */
class MultipartFormData {
  #boundary = `----------------------------${randomBytes(16).toString("hex")}`;
  #parts = [];

  append(name, value, { filename, contentType } = {}) {
    let header = `--${this.#boundary}\r\nContent-Disposition: form-data; name="${name}"`;
    if (filename) {
      header += `; filename="${filename}"`;
    }
    if (contentType) {
      header += `\r\nContent-Type: ${contentType}`;
    }
    header += "\r\n\r\n";
    const valueBuffer = Buffer.isBuffer(value)
      ? value
      : Buffer.from(String(value));
    this.#parts.push(Buffer.from(header), valueBuffer, Buffer.from("\r\n"));
  }

  getBuffer() {
    return Buffer.concat([
      ...this.#parts,
      Buffer.from(`--${this.#boundary}--\r\n`),
    ]);
  }

  getHeaders() {
    return {
      "content-type": `multipart/form-data; boundary=${this.#boundary}`,
    };
  }
}

/**
 * Returns the Dependency-Track BOM API URL as a sanitized URL object.
 *
 * @param {string} serverUrl Dependency-Track server URL
 * @returns {URL | undefined} API URL to submit BOM payload
 */
export function getDependencyTrackBomApiUrl(serverUrl) {
  const rawServerUrl = `${serverUrl || ""}`.trim();
  if (!rawServerUrl || hasDangerousUnicode(rawServerUrl)) {
    return undefined;
  }
  let parsedUrl;
  try {
    parsedUrl = new URL(rawServerUrl);
  } catch {
    return undefined;
  }
  if (!["http:", "https:"].includes(parsedUrl.protocol)) {
    return undefined;
  }
  if (!parsedUrl.hostname || hasDangerousUnicode(parsedUrl.hostname)) {
    return undefined;
  }
  parsedUrl.username = "";
  parsedUrl.password = "";
  parsedUrl.search = "";
  parsedUrl.hash = "";
  parsedUrl.pathname = `${parsedUrl.pathname.replace(/\/+$/, "")}/api/v1/bom`;
  return parsedUrl;
}

/**
 * Returns the Dependency-Track BOM API URL string.
 *
 * @param {string} serverUrl Dependency-Track server URL
 * @returns {string | undefined} API URL to submit BOM payload
 */
export function getDependencyTrackBomUrl(serverUrl) {
  return getDependencyTrackBomApiUrl(serverUrl)?.toString();
}

/**
 * Build multipart/form-data payload for Dependency-Track BOM submission.
 *
 * @param {Object} args CLI/server arguments
 * @param {Object} bomContents BOM Json
 * @returns {FormData | undefined} FormData object if project coordinates are valid
 */
export function buildDependencyTrackBomPayload(args, bomContents) {
  const autoCreate =
    typeof args.autoCreate === "boolean"
      ? args.autoCreate
      : args.autoCreate !== "false";

  // Validate BOM contents
  if (!bomContents) {
    return undefined;
  }

  // Validate project coordinates
  if (
    typeof args.projectId === "undefined" &&
    typeof args.projectName === "undefined"
  ) {
    return undefined;
  }

  const parentProjectId = args.parentProjectId || args.parentUUID;
  const hasParentUuidMode = typeof parentProjectId !== "undefined";
  const hasParentName = typeof args.parentProjectName !== "undefined";
  const hasParentVersion = typeof args.parentProjectVersion !== "undefined";
  const hasParentCoordsMode = hasParentName || hasParentVersion;
  if (hasParentUuidMode && hasParentCoordsMode) {
    return undefined;
  }
  if (!hasParentUuidMode && hasParentName !== hasParentVersion) {
    return undefined;
  }

  const formData = new MultipartFormData();

  // Add BOM file
  const bomJsonString = JSON.stringify(bomContents);
  const bomBuffer = Buffer.from(bomJsonString);
  formData.append("bom", bomBuffer, {
    filename: "bom.json",
    contentType: "application/json",
  });

  // Add form fields
  formData.append("autoCreate", String(autoCreate));

  if (typeof args.projectId !== "undefined") {
    formData.append("project", args.projectId);
  }
  if (typeof args.projectName !== "undefined") {
    formData.append("projectName", args.projectName);
  }
  // Dependency-Track submissions use "main" as fallback when no version is provided.
  formData.append("projectVersion", args.projectVersion || "main");

  if (hasParentUuidMode) {
    formData.append("parentUUID", parentProjectId);
  }
  if (hasParentName && hasParentVersion) {
    formData.append("parentName", args.parentProjectName);
    formData.append("parentVersion", args.parentProjectVersion);
  }
  if (
    typeof args.isLatest === "boolean" ||
    args.isLatest === "true" ||
    args.isLatest === "false"
  ) {
    const isLatest =
      typeof args.isLatest === "boolean"
        ? args.isLatest
        : args.isLatest === "true";
    formData.append("isLatest", String(isLatest));
  }
  if (typeof args.projectTag !== "undefined") {
    const tags = Array.isArray(args.projectTag)
      ? args.projectTag
      : [args.projectTag];
    formData.append(
      "projectTags",
      JSON.stringify(tags.map((tag) => ({ name: tag }))),
    );
  }

  return formData;
}
