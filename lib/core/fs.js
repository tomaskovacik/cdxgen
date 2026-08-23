import { Buffer } from "node:buffer";
import { spawnSync } from "node:child_process";
import { createHash, randomUUID } from "node:crypto";
import {
  copyFileSync,
  createReadStream,
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import path, { basename, dirname, join, resolve } from "node:path";
import process from "node:process";

import { Glob, globSync } from "glob";

import {
  buildReadCountSuffix,
  classifyActivityPath,
  classifyDiscoveryPattern,
  createDryRunError,
  DEBUG_MODE,
  isDryRun,
  isSecureMode,
  readEnvironmentVariable,
  recordActivity,
  recordDiscoveryActivity,
  recordFilesystemActivity,
  recordObservedActivity,
  recordPolicyActivity,
} from "./activity.js";
import { thoughtLog, traceLog } from "./logger.js";
import { isWin } from "./paths.js";

function getArchiveSourceByteSize(sourcePath) {
  if (!sourcePath || !safeExistsSync(sourcePath)) {
    return undefined;
  }
  try {
    const sourceStats = lstatSync(sourcePath);
    return sourceStats.isFile() ? sourceStats.size : undefined;
  } catch {
    return undefined;
  }
}

function hasReadPermission(filePath) {
  if (!(isSecureMode && process.permission)) {
    return true;
  }
  return process.permission.has("fs.read", join(filePath, "", "*"));
}

function hasWritePermission(filePath) {
  if (!(isSecureMode && process.permission)) {
    return true;
  }
  const candidatePaths = [
    filePath,
    join(filePath, "", "*"),
    join(dirname(filePath), "*"),
  ];
  return candidatePaths.some((candidatePath) =>
    process.permission.has("fs.write", candidatePath),
  );
}
/**
 * Safely check if a file path exists without crashing due to a lack of permissions
 *
 * @param {String} filePath File path
 * @Boolean True if the path exists. False otherwise
 */
export function safeExistsSync(filePath) {
  const pathMetadata = classifyActivityPath(filePath);
  if (!hasReadPermission(filePath)) {
    if (DEBUG_MODE) {
      console.log("cdxgen lacks read permission for a requested path.");
    }
    if (pathMetadata) {
      recordPolicyActivity(filePath, {
        metadata: {
          classification: pathMetadata.classification,
          ecosystem: pathMetadata.ecosystem,
          policyType: "fs.read",
        },
        reason: `Denied inspection of ${pathMetadata.label} ${filePath} due to missing fs.read permission.`,
        status: "blocked",
      });
    }
    return false;
  }
  const exists = existsSync(filePath);
  if (pathMetadata) {
    const inspectionKind =
      pathMetadata.classification === "directory" ? "discover" : "inspect";
    recordObservedActivity(inspectionKind, filePath, {
      metadata: {
        classification: pathMetadata.classification,
        ecosystem: pathMetadata.ecosystem,
        exists,
        redacted: pathMetadata.sensitive ?? false,
      },
      reasonBuilder: (count) =>
        `${exists ? "Inspected" : "Checked for"} ${pathMetadata.label} ${filePath}${buildReadCountSuffix(count)}.`,
    });
  }
  return exists;
}

/**
 * Permission- and dry-run-aware wrapper around writeFileSync. Records the
 * activity and returns undefined when blocked.
 *
 * @param {string} filePath File path to write.
 * @param {string|Buffer} data Data to write.
 * @param {Object} [options] writeFileSync options (encoding, mode, flag).
 * @returns {void}
 */
export function safeWriteSync(filePath, data, options) {
  if (isDryRun) {
    recordFilesystemActivity(
      "write",
      filePath,
      "blocked",
      "Dry run mode blocks filesystem writes.",
    );
    return undefined;
  }
  if (!hasWritePermission(filePath)) {
    if (DEBUG_MODE) {
      console.log("cdxgen lacks write permission for a requested path.");
    }
    recordFilesystemActivity(
      "write",
      filePath,
      "blocked",
      "cdxgen lacks write permission for this path.",
    );
    return undefined;
  }
  writeFileSync(filePath, data, options);
  recordFilesystemActivity("write", filePath, "completed");
}

/**
 * Safely create a directory without crashing due to a lack of permissions
 *
 * @param {String} filePath File path
 * @param options {Options} mkdir options
 * @Boolean True if the path exists. False otherwise
 */
export function safeMkdirSync(filePath, options) {
  if (isDryRun) {
    recordFilesystemActivity(
      "mkdir",
      filePath,
      "blocked",
      "Dry run mode blocks directory creation.",
    );
    return undefined;
  }
  if (!hasWritePermission(filePath)) {
    if (DEBUG_MODE) {
      console.log("cdxgen lacks write permission for a requested path.");
    }
    recordFilesystemActivity(
      "mkdir",
      filePath,
      "blocked",
      "cdxgen lacks write permission for this path.",
    );
    return undefined;
  }
  mkdirSync(filePath, options);
  recordFilesystemActivity("mkdir", filePath, "completed");
}

/**
 * Dry-run-aware wrapper around mkdtempSync that records the activity. In dry-run
 * mode, returns a synthetic path without touching the filesystem.
 *
 * @param {string} prefix Path prefix for the temporary directory.
 * @param {string|Object} [options] Encoding or mkdtempSync options.
 * @returns {string|undefined} The created directory path, a synthetic path in dry-run mode, or undefined when blocked.
 */
export function safeMkdtempSync(prefix, options = undefined) {
  const resourceType =
    typeof prefix === "string" && prefix.toLowerCase().includes("cache")
      ? "cache"
      : "temporary-workspace";
  if (isDryRun) {
    const tempPath = `${prefix}${randomUUID().replaceAll("-", "").slice(0, 6)}`;
    recordFilesystemActivity(
      "temp-dir",
      tempPath,
      "blocked",
      `Dry run mode blocks temporary directory creation for ${resourceType}.`,
      {
        resourceType,
      },
    );
    return tempPath;
  }
  const tempPath = mkdtempSync(prefix, options);
  recordFilesystemActivity("temp-dir", tempPath, "completed", undefined, {
    resourceType,
  });
  return tempPath;
}

/**
 * Dry-run-aware wrapper around rmSync. Records the activity and returns
 * undefined when blocked.
 *
 * @param {string} filePath Path to remove.
 * @param {Object} [options] rmSync options (recursive, force, etc.).
 * @returns {void}
 */
export function safeRmSync(filePath, options = undefined) {
  if (isDryRun) {
    recordFilesystemActivity(
      "cleanup",
      filePath,
      "blocked",
      "Dry run mode blocks filesystem deletions.",
    );
    return undefined;
  }
  rmSync(filePath, options);
  recordFilesystemActivity("cleanup", filePath, "completed");
}

/**
 * Dry-run-aware wrapper around unlinkSync. Records the activity and returns
 * undefined when blocked.
 *
 * @param {string} filePath File path to unlink.
 * @returns {void}
 */
export function safeUnlinkSync(filePath) {
  if (isDryRun) {
    recordFilesystemActivity(
      "cleanup",
      filePath,
      "blocked",
      "Dry run mode blocks file deletions.",
    );
    return undefined;
  }
  unlinkSync(filePath);
  recordFilesystemActivity("cleanup", filePath, "completed");
}

/**
 * Dry-run-aware wrapper around copyFileSync. Records the activity and returns
 * undefined when blocked.
 *
 * @param {string} src Source file path.
 * @param {string} dest Destination file path.
 * @param {number} [mode] Optional copy mode bitmask.
 * @returns {void}
 */
export function safeCopyFileSync(src, dest, mode = undefined) {
  if (isDryRun) {
    recordFilesystemActivity(
      "write",
      dest,
      "blocked",
      `Dry run mode blocks copying files from ${src}.`,
    );
    return undefined;
  }
  const result =
    mode === undefined
      ? copyFileSync(src, dest)
      : copyFileSync(src, dest, mode);
  recordFilesystemActivity("write", dest, "completed", `Copied from ${src}.`);
  return result;
}

/**
 * Run an archive extractor under dry-run/debug activity tracing. In dry-run
 * mode the extraction is recorded as blocked and resolves false without running.
 *
 * @param {string} sourcePath Path to the source archive.
 * @param {string} targetPath Path to extract into.
 * @param {() => Promise} extractor Async function performing the extraction.
 * @param {string} [kind="unzip"] Archive kind label for tracing.
 * @param {Object} [options] Optional tracing metadata, blockedReason, and failureReason.
 * @returns {Promise<boolean>} True when extraction succeeded, false when blocked by dry-run.
 */
export async function safeExtractArchive(
  sourcePath,
  targetPath,
  extractor,
  kind = "unzip",
  options = undefined,
) {
  const traceArchiveStats = isDryRun || DEBUG_MODE;
  const sourceBytes = traceArchiveStats
    ? getArchiveSourceByteSize(sourcePath)
    : undefined;
  if (isDryRun) {
    recordActivity({
      archiveKind: kind,
      capability: "archive-extraction",
      kind,
      ...(options?.metadata || {}),
      ...(sourceBytes !== undefined ? { sourceBytes } : {}),
      reason:
        options?.blockedReason ||
        `Dry run mode blocks ${kind} extraction from ${sourcePath} into ${targetPath}.`,
      status: "blocked",
      target: `${sourcePath} -> ${targetPath}`,
    });
    return false;
  }
  try {
    await extractor();
    recordActivity({
      archiveKind: kind,
      capability: "archive-extraction",
      kind,
      ...(options?.metadata || {}),
      ...(sourceBytes !== undefined ? { sourceBytes } : {}),
      status: "completed",
      target: `${sourcePath} -> ${targetPath}`,
    });
    return true;
  } catch (error) {
    recordActivity({
      archiveKind: kind,
      capability: "archive-extraction",
      kind,
      ...(options?.metadata || {}),
      ...(sourceBytes !== undefined ? { sourceBytes } : {}),
      ...(error?.code ? { errorCode: error.code } : {}),
      reason:
        options?.failureReason ||
        `Failed ${kind} extraction from ${sourcePath} into ${targetPath}: ${error.message}`,
      status: "failed",
      target: `${sourcePath} -> ${targetPath}`,
    });
    throw error;
  }
}

/** Set of temporary file paths written by cdxgen that are removed on process exit. */
export const temporaryFiles = new Set();
process.on("exit", () =>
  temporaryFiles.forEach((tempFile) => {
    if (safeExistsSync(tempFile)) {
      safeUnlinkSync(tempFile);
    }
  }),
);

/** Set accumulating every executable command spawned via safeSpawnSync. */
export const commandsExecuted = new Set();
function isAllowedCommand(
  command,
  allowedCommandsEnv = readEnvironmentVariable("CDXGEN_ALLOWED_COMMANDS"),
) {
  if (!allowedCommandsEnv) {
    return true;
  }
  const trimmedCommand = command.trim();
  return allowedCommandsEnv
    .split(",")
    .map((entry) => entry.trim())
    .some((pattern) => {
      // Exact match for backward compatibility
      if (pattern === trimmedCommand) {
        return true;
      }
      // Try regex match if pattern looks like a regex pattern
      try {
        const regex = new RegExp(pattern);
        return regex.test(trimmedCommand);
      } catch {
        // Invalid regex, skip
        return false;
      }
    });
}

const ALLOWED_WRAPPERS = new Set(["gradlew", "mvnw"]);

/**
 * Check for Windows CWD executable hijack when shell: true is used.
 * cmd.exe searches CWD before PATH, allowing local files to shadow system commands.
 *
 * @param {string} command The executable to spawn
 * @param {Object} options Options forwarded to spawnSync (e.g. cwd, env, shell)
 *
 * @returns {boolean} true if there is a hijack risk. false otherwise.
 */
function isWindowsShellHijackRisk(command, options) {
  const cwd = options?.cwd;
  const usesShell = options?.shell === true;
  if (!isWin || !usesShell || !cwd || !command) {
    return false;
  }
  if (/[\/\\]/.test(command)) {
    return false;
  }
  const cmdBase = command.toLowerCase();
  if (ALLOWED_WRAPPERS.has(cmdBase)) {
    return false;
  }
  const pathExt = (
    readEnvironmentVariable("PATHEXT") ||
    ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC"
  )
    .split(";")
    .filter(Boolean);
  const candidates = [
    cmdBase,
    ...pathExt.map((ext) => cmdBase + ext.toLowerCase()),
  ];
  const absCwd = resolve(cwd);
  for (const candidate of candidates) {
    const candidatePath = path.join(absCwd, candidate);
    if (existsSync(candidatePath)) {
      return true;
    }
  }
  return false;
}

const VERSION_PROBE_ARGS = new Set(["--version", "-version", "version"]);

const POSIX_SHELL_METACHARACTERS = /[;&|<>$`\\\n\r]/;
const WINDOWS_SHELL_METACHARACTERS = /[&|<>^%\n\r]/;

function hasShellMetacharacters(value) {
  if (value === undefined || value === null) {
    return false;
  }
  const stringValue = String(value);
  return isWin
    ? WINDOWS_SHELL_METACHARACTERS.test(stringValue)
    : POSIX_SHELL_METACHARACTERS.test(stringValue);
}

function getUnsafeShellToken(command, args) {
  if (hasShellMetacharacters(command)) {
    return command;
  }
  const argList = Array.isArray(args)
    ? args
    : args === undefined || args === null
      ? []
      : [args];
  return argList.find((arg) => hasShellMetacharacters(arg));
}

function recordSuspiciousShellPathActivities(files, metadata = {}) {
  for (const file of files) {
    if (!hasShellMetacharacters(file)) {
      continue;
    }
    recordActivity({
      classification: "suspicious-path",
      discoveryType: metadata.discoveryType,
      kind: "inspect",
      pattern: metadata.pattern,
      reason:
        "Suspicious path contains shell metacharacters. cdxgen passes direct process arguments as argv values, but review this path before invoking external build tools on untrusted projects.",
      risk: "shell-metacharacters",
      status: "completed",
      target: file,
    });
  }
}

function detectProbeType(command, args = []) {
  const normalizedCommand = basename(String(command || "")).toLowerCase();
  const normalizedArgs = (args || []).map((arg) => String(arg).toLowerCase());
  if (
    normalizedArgs.some((arg) => VERSION_PROBE_ARGS.has(arg)) ||
    (normalizedArgs.length === 1 && normalizedArgs[0] === "-v")
  ) {
    return "version-check";
  }
  if (normalizedCommand === "which" || normalizedArgs.includes("--help")) {
    return "capability-probe";
  }
  if (
    normalizedCommand.startsWith("python") &&
    normalizedArgs.includes("-c") &&
    normalizedArgs.some((arg) => arg.includes("import"))
  ) {
    return "runtime-probe";
  }
  return undefined;
}

function buildCommandActivityDescriptor(command, args, options) {
  const target = `${command}${args?.length ? ` ${args.join(" ")}` : ""}`;
  const cdxgenActivity = options?.cdxgenActivity || {};
  const probeType = cdxgenActivity.probeType || detectProbeType(command, args);
  const metadata = {
    ...(cdxgenActivity.metadata || {}),
  };
  if (probeType) {
    metadata.capability = metadata.capability || "tool-runtime-probe";
    metadata.probeType = probeType;
  }
  if (cdxgenActivity.gitOperation) {
    metadata.gitOperation = cdxgenActivity.gitOperation;
  }
  return {
    blockedReason:
      cdxgenActivity.blockedReason ||
      (probeType
        ? `Dry run mode blocks ${probeType.replaceAll("-", " ")} command execution.`
        : "Dry run mode blocks child process execution."),
    kind: cdxgenActivity.kind || "execute",
    metadata,
    target: cdxgenActivity.target || target,
  };
}

function getOutputByteSize(value, encoding = "utf-8") {
  if (value === undefined || value === null) {
    return 0;
  }
  if (Buffer.isBuffer(value)) {
    return value.length;
  }
  if (ArrayBuffer.isView(value)) {
    return value.byteLength;
  }
  const safeEncoding =
    typeof encoding === "string" && encoding !== "buffer" ? encoding : "utf8";
  return Buffer.byteLength(String(value), safeEncoding);
}

/**
 * Safe wrapper around spawnSync that enforces permission checks, injects default
 * options (maxBuffer, encoding, timeout), warns about unsafe Python and pip/uv
 * invocations, and records every executed command in the commandsExecuted set.
 *
 * @param {string} command The executable to spawn
 * @param {string[]} args Arguments to pass to the command
 * @param {Object} options Options forwarded to spawnSync (e.g. cwd, env, shell)
 * @returns {Object} spawnSync result object with status, stdout, stderr, and error fields
 */
export function safeSpawnSync(command, args, options) {
  const activityDescriptor = buildCommandActivityDescriptor(
    command,
    args,
    options,
  );
  const allowedCommandsEnv = readEnvironmentVariable("CDXGEN_ALLOWED_COMMANDS");
  const commandAllowed = isAllowedCommand(command, allowedCommandsEnv);
  if (allowedCommandsEnv) {
    recordPolicyActivity(command, {
      metadata: {
        allowed: commandAllowed,
        allowlist: allowedCommandsEnv,
        policyType: "command-allowlist",
      },
      reason: `${commandAllowed ? "Allowed" : "Blocked"} command ${command} against CDXGEN_ALLOWED_COMMANDS.`,
      status: commandAllowed ? "completed" : "blocked",
      traceDetail: "allowlist",
    });
  }
  if (isSecureMode && process.permission) {
    const hasChildPermission = process.permission.has("child");
    recordPolicyActivity(command, {
      metadata: {
        allowed: hasChildPermission,
        policyType: "child-process",
      },
      reason: `${hasChildPermission ? "Confirmed" : "Denied"} child-process permission for ${command}.`,
      status: hasChildPermission ? "completed" : "blocked",
      traceDetail: "child-permission",
    });
  }
  if (isDryRun) {
    const error = createDryRunError(
      "execute",
      command,
      activityDescriptor.blockedReason,
    );
    recordActivity({
      kind: activityDescriptor.kind,
      ...activityDescriptor.metadata,
      reason: error.message,
      status: "blocked",
      target: activityDescriptor.target,
    });
    return {
      status: 1,
      stdout: undefined,
      stderr: undefined,
      error,
    };
  }
  if (
    (isSecureMode && process.permission && !process.permission.has("child")) ||
    !commandAllowed
  ) {
    if (DEBUG_MODE) {
      console.log(`cdxgen lacks execute permission for ${command}`);
    }
    recordActivity({
      kind: activityDescriptor.kind,
      ...activityDescriptor.metadata,
      reason: "cdxgen lacks execute permission for this command.",
      status: "blocked",
      target: activityDescriptor.target,
    });
    return {
      status: 1,
      stdout: undefined,
      stderr: undefined,
      error: new Error("No execute permission"),
    };
  }
  if (isSecureMode) {
    if (isWindowsShellHijackRisk(command, options)) {
      const blockedReason = `${command} matches local file in cwd (Windows shell hijack risk)`;
      console.warn(`\x1b[1;31mSecurity Alert: ${blockedReason}\x1b[0m`);
      recordActivity({
        kind: activityDescriptor.kind,
        ...activityDescriptor.metadata,
        reason: blockedReason,
        status: "blocked",
        target: activityDescriptor.target,
      });
      return {
        status: 1,
        stdout: undefined,
        stderr: undefined,
        error: new Error(blockedReason),
      };
    }
    if (options?.cwd && options.cwd !== resolve(options.cwd)) {
      if (DEBUG_MODE) {
        console.log(
          "Executing commands with a relative cwd can cause security issues.",
        );
      }
    }
  }
  if (!options) {
    options = {};
  } else if (options.cdxgenActivity) {
    options = {
      ...options,
    };
  }
  if (options.cdxgenActivity) {
    delete options.cdxgenActivity;
  }
  if (options.shell === true) {
    const unsafeShellToken = getUnsafeShellToken(command, args);
    if (unsafeShellToken !== undefined) {
      const blockedReason = `Blocked shell execution for ${command}: command or argument contains shell metacharacters.`;
      console.warn(`\x1b[1;31mSecurity Alert: ${blockedReason}\x1b[0m`);
      recordActivity({
        kind: activityDescriptor.kind,
        ...activityDescriptor.metadata,
        reason: blockedReason,
        status: "blocked",
        target: activityDescriptor.target,
      });
      return {
        status: 1,
        stdout: undefined,
        stderr: undefined,
        error: new Error(blockedReason),
      };
    }
  }
  // Inject maxBuffer
  if (!options.maxBuffer) {
    options.maxBuffer = MAX_BUFFER;
  }
  // Inject encoding
  if (!options.encoding) {
    options.encoding = "utf-8";
  }
  // Inject timeout
  if (!options.timeout) {
    options.timeout = TIMEOUT_MS;
  }
  // Emit certain operational warnings only once per process to keep audit logs readable.
  const emitNoticeOnce = (noticeKey, message, level = "warn") => {
    if (!globalThis.__cdxgenNoticeCache) {
      globalThis.__cdxgenNoticeCache = new Set();
    }
    if (globalThis.__cdxgenNoticeCache.has(noticeKey)) {
      return;
    }
    globalThis.__cdxgenNoticeCache.add(noticeKey);
    if (level === "log") {
      console.log(message);
      return;
    }
    console.warn(message);
  };
  // Check for -S for python invocations in secure mode
  if (command.includes("python") && (!args?.length || args[0] !== "-S")) {
    if (isSecureMode) {
      emitNoticeOnce(
        "python-without-S-secure",
        "\x1b[1;35mNotice: Running python command without '-S' argument. This is a bug in cdxgen. Please report with an example repo here https://github.com/cdxgen/cdxgen/issues.\x1b[0m",
      );
    } else if (readEnvironmentVariable("CDXGEN_IN_CONTAINER") === "true") {
      emitNoticeOnce(
        "python-without-S-container",
        "Running python command without '-S' argument.",
        "log",
      );
    } else {
      emitNoticeOnce(
        "python-without-S-host",
        "\x1b[1;35mNotice: Running python command without '-S' argument. Only run cdxgen in trusted directories to prevent auto-executing local scripts.\x1b[0m",
      );
    }
  }
  let isPyPackageInstall = false;
  if (command.includes("pip") && args?.includes("install")) {
    isPyPackageInstall = true;
  } else if (
    command.includes("python") &&
    args?.includes("pip") &&
    args?.includes("install")
  ) {
    isPyPackageInstall = true;
  } else if (
    command.includes("uv") &&
    args?.includes("pip") &&
    args?.includes("install")
  ) {
    isPyPackageInstall = true;
  }
  if (isPyPackageInstall) {
    const hasOnlyBinary = args?.some(
      (arg) => arg === "--only-binary" || arg.startsWith("--only-binary="),
    );
    if (!hasOnlyBinary) {
      if (isSecureMode) {
        emitNoticeOnce(
          "pip-without-only-binary-secure",
          "\x1b[1;31mSecurity Alert: pip/uv install invoked without '--only-binary' argument in secure mode. This is a bug in cdxgen and introduces Arbitrary Code Execution (ACE) risks. Please report with an example repo here https://github.com/cdxgen/cdxgen/issues.\x1b[0m",
        );
      } else if (readEnvironmentVariable("CDXGEN_IN_CONTAINER") === "true") {
        emitNoticeOnce(
          "pip-without-only-binary-container",
          "Running pip/uv install without '--only-binary' argument.",
          "log",
        );
      } else {
        emitNoticeOnce(
          "pip-without-only-binary-host",
          "\x1b[1;35mNotice: pip/uv install invoked without '--only-binary'. This allows executing untrusted setup.py scripts. Only run cdxgen in trusted directories.\x1b[0m",
        );
      }
    }
  }
  traceLog("spawn", { command, args, ...options });
  commandsExecuted.add(command);
  // Fix for DEP0190 warning
  if (options?.shell === true) {
    if (args?.length) {
      command = `${command} ${args.join(" ")}`;
      args = undefined;
    }
  }
  const result = spawnSync(command, args, options);
  recordActivity({
    kind: activityDescriptor.kind,
    ...activityDescriptor.metadata,
    stderrBytes: getOutputByteSize(result.stderr, options.encoding),
    reason: result.error?.message,
    status: result.status === 0 && !result.error ? "completed" : "failed",
    stdoutBytes: getOutputByteSize(result.stdout, options.encoding),
    target: activityDescriptor.target,
  });
  return result;
}

/** Default spawn timeout in milliseconds (20 minutes), overridable via CDXGEN_TIMEOUT_MS. */
export const TIMEOUT_MS =
  Number.parseInt(readEnvironmentVariable("CDXGEN_TIMEOUT_MS"), 10) ||
  20 * 60 * 1000;

/** Default maxBuffer size for spawned process stdout/stderr (100 MB), overridable via CDXGEN_MAX_BUFFER. */
export const MAX_BUFFER =
  Number.parseInt(readEnvironmentVariable("CDXGEN_MAX_BUFFER"), 10) ||
  100 * 1024 * 1024;

/**
 * Method to get files matching a pattern
 *
 * @param {string} dirPath Root directory for search
 * @param {string} pattern Glob pattern (eg: *.gradle)
 * @param {Object} options CLI options
 *
 * @returns {Array[string]} List of matched files
 */
export function getAllFiles(dirPath, pattern, options = {}) {
  let ignoreList = [];
  if (!options.noIgnore) {
    ignoreList.push("**/.hg/**", "**/.git/**");
    // Only ignore node_modules if the caller is not looking for package.json
    if (!pattern.includes("package.json") && !options.includeNodeModulesDir) {
      ignoreList.push("**/node_modules/**");
    } else if (options.includeNodeModulesDir === false) {
      ignoreList.push("**/node_modules/**");
    }
  }
  if (options?.exclude && Array.isArray(options.exclude)) {
    ignoreList = ignoreList.concat(options.exclude);
  }
  const includeDot =
    options.includeDot ||
    pattern.startsWith(".") ||
    options.includeNodeModulesDir ||
    options.noIgnore;
  const defaultHits = getAllFilesWithIgnore(
    dirPath,
    pattern,
    includeDot,
    ignoreList,
  );
  // Support for specifying the pattern via options
  if (options?.include?.length) {
    const includeOnlyHits = getAllFilesWithIgnore(
      dirPath,
      options.include,
      includeDot,
      ignoreList,
    );
    if (!includeOnlyHits.length) {
      return [];
    }
    return defaultHits.filter((f) => includeOnlyHits.includes(f));
  }
  return defaultHits;
}

/**
 * Directory-walk caches, keyed by the root each walk starts from, and the one
 * subtree they may be used for.
 *
 * A container scan enumerates the same rootfs path from about 25 ecosystem
 * legs, each with a different glob pattern. `glob` reads the tree through a
 * `PathScurry`, which memoises `readdir` and `lstat` per directory, so handing
 * every call for a root the same instance turns those repeated walks into one
 * walk followed by in-memory lookups. Pattern matching, ignore handling,
 * ordering and dotfile rules all stay inside `glob`.
 *
 * Memoised directory entries describe the tree as it was first read, so they
 * may only be reused where nothing changes during the scan. That holds for the
 * exploded image layers, which are written once by the extractor and read from
 * then on, and not for a source tree, where a build tool invoked by one
 * ecosystem writes the lock file another goes on to look for. Caching is
 * therefore confined to a subtree named by {@link setDirWalkCacheRoot}.
 *
 * A `PathScurry` is bound to the case sensitivity it was built with, so the
 * cache holds one per root for the `nocase` walks issued from here.
 */
const dirWalkCache = new Map();
let dirWalkCacheRoot;

/**
 * Confine directory-walk caching to one subtree, or switch it off.
 *
 * @param {string|undefined} rootDir Subtree whose contents are fixed for the rest of the scan
 */
export function setDirWalkCacheRoot(rootDir) {
  if (rootDir !== dirWalkCacheRoot) {
    dirWalkCache.clear();
  }
  dirWalkCacheRoot = rootDir || undefined;
}

/**
 * Return the shared directory-walk cache for a root, creating it on first use.
 *
 * Constructing a `Glob` does not touch the filesystem; it is the supported way
 * to obtain the `PathScurry` that `glob` would otherwise build per call.
 *
 * @param {string} dirPath Root directory the walk starts from
 * @returns {object|undefined} Cache to pass to `globSync`, or undefined when the path is not cacheable
 */
function getDirWalkCache(dirPath) {
  if (!(dirWalkCacheRoot && dirPath?.startsWith(dirWalkCacheRoot))) {
    return undefined;
  }
  if (dirWalkCache.has(dirPath)) {
    return dirWalkCache.get(dirPath);
  }
  let scurry;
  try {
    scurry = new Glob("**/*", { cwd: dirPath, nocase: true }).scurry;
  } catch (_err) {
    scurry = undefined;
  }
  dirWalkCache.set(dirPath, scurry);
  return scurry;
}

/**
 * Release every cached directory walk.
 *
 * Called when a BOM generation cycle starts, so that a long-lived process such
 * as the server never serves a scan from an earlier scan's view of the
 * filesystem, and so the retained directory entries are freed.
 */
export function clearFileDiscoveryCache() {
  dirWalkCache.clear();
  dirWalkCacheRoot = undefined;
}

/**
 * Method to get files matching a pattern
 *
 * @param {string} dirPath Root directory for search
 * @param {string} pattern Glob pattern (eg: *.gradle)
 * @param {Boolean} includeDot whether hidden files can be included.
 * @param {Array} ignoreList Directory patterns to ignore
 *
 * @returns {Array[string]} List of matched files
 */
export function getAllFilesWithIgnore(
  dirPath,
  pattern,
  includeDot,
  ignoreList,
) {
  const patternValue = Array.isArray(pattern)
    ? pattern.join(",")
    : String(pattern);
  const discoveryMetadata = classifyDiscoveryPattern(patternValue);
  try {
    const files = globSync(pattern, {
      cwd: dirPath,
      absolute: true,
      nocase: true,
      nodir: true,
      dot: includeDot,
      follow: false,
      ignore: ignoreList,
      scurry: getDirWalkCache(dirPath),
    });
    recordDiscoveryActivity(`${dirPath} :: ${patternValue}`, {
      metadata: {
        discoveryType: discoveryMetadata.discoveryType,
        matchedCount: files.length,
        pattern: patternValue,
      },
      traceDetail: `matched:${files.length}`,
      reasonBuilder: (count) =>
        `Scanned ${dirPath} with glob '${patternValue}' for ${discoveryMetadata.label}; matched ${files.length} path(s)${buildReadCountSuffix(count)}.`,
    });
    recordSuspiciousShellPathActivities(files, {
      discoveryType: discoveryMetadata.discoveryType,
      pattern: patternValue,
    });
    if (files.length > 1) {
      thoughtLog(
        `Found ${files.length} files for the pattern '${pattern}' at '${dirPath}'.`,
      );
    }
    return files;
  } catch (err) {
    recordDiscoveryActivity(`${dirPath} :: ${patternValue}`, {
      metadata: {
        discoveryType: discoveryMetadata.discoveryType,
        pattern: patternValue,
      },
      reason: `File discovery failed for glob '${patternValue}' under ${dirPath}: ${err.message}`,
      status: "failed",
    });
    if (DEBUG_MODE) {
      console.error(err);
    }
    return [];
  }
}

/**
 * Return the current timestamp in YYYY-MM-DDTHH:MM:SSZ format.
 *
 * @returns {string} ISO formatted timestamp, without milliseconds.
 */
export function getTimestamp() {
  return `${new Date().toISOString().split(".")[0]}Z`;
}

/**
 * Return the temp directory, creating CDXGEN_TEMP_DIR when it is set but does
 * not yet exist. Falls back to the OS tmpdir when unset.
 *
 * @returns {string} Resolved temp directory path.
 */
export function getTmpDir() {
  if (
    readEnvironmentVariable("CDXGEN_TEMP_DIR") &&
    !safeExistsSync(readEnvironmentVariable("CDXGEN_TEMP_DIR"))
  ) {
    safeMkdirSync(readEnvironmentVariable("CDXGEN_TEMP_DIR"), {
      recursive: true,
    });
  }
  return readEnvironmentVariable("CDXGEN_TEMP_DIR") || tmpdir();
}

/**
 * Computes the checksum for a file path using the given hash algorithm
 *
 * @param {string} hashName name of hash algorithm
 * @param {string} path path to file
 * @returns {Promise<String>} hex value of hash
 */
export function checksumFile(hashName, path) {
  return new Promise((resolve, reject) => {
    const hash = createHash(hashName);
    const stream = createReadStream(path);
    stream.on("error", (err) => reject(err));
    stream.on("data", (chunk) => hash.update(chunk));
    stream.on("end", () => resolve(hash.digest("hex")));
  });
}

/**
 * Computes multiple checksum for a file path using the given hash algorithms
 *
 * @param {Array[String]} algorithms Array of algorithms
 * @param {string} path path to file
 * @returns {Promise<Object>} hashes object
 */
export function multiChecksumFile(algorithms, path) {
  return new Promise((resolve, reject) => {
    const hashes = {};
    for (const alg of algorithms) {
      hashes[alg] = createHash(alg);
    }
    const stream = createReadStream(path);
    let errorOccurred = false;
    stream.on("error", (err) => {
      errorOccurred = true;
      reject(err);
    });
    stream.on("data", (chunk) =>
      algorithms.forEach((alg) => {
        hashes[alg].update(chunk);
      }),
    );
    stream.on("end", () => {
      algorithms.forEach((alg) => {
        hashes[alg] = hashes[alg].digest("hex");
      });
    });
    stream.on("close", () => {
      if (!errorOccurred) {
        resolve(hashes);
      }
    });
  });
}
