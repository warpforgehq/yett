#!/usr/bin/env node
"use strict";

const { spawnSync } = require("node:child_process");

const PLATFORM_PACKAGES = {
  "linux-x64": "@warpforge/yett-linux-x64",
  "linux-arm64": "@warpforge/yett-linux-arm64",
  "darwin-x64": "@warpforge/yett-darwin-x64",
  "darwin-arm64": "@warpforge/yett-darwin-arm64",
};

const key = `${process.platform}-${process.arch}`;
const pkg = PLATFORM_PACKAGES[key];

if (!pkg) {
  console.error(
    `yett does not ship a binary for ${key}. Supported: ${Object.keys(
      PLATFORM_PACKAGES,
    ).join(", ")}.`,
  );
  process.exit(1);
}

let binary;
try {
  binary = require.resolve(`${pkg}/bin/yett`);
} catch {
  console.error(
    `yett could not load its ${key} binary package (${pkg}). ` +
      "Reinstall without --no-optional, or install that package directly.",
  );
  process.exit(1);
}

const result = spawnSync(binary, process.argv.slice(2), { stdio: "inherit" });

if (result.error) {
  console.error(`yett failed to run ${binary}: ${result.error.message}`);
  process.exit(1);
}

if (result.signal) {
  process.kill(process.pid, result.signal);
}

process.exit(result.status === null ? 1 : result.status);
