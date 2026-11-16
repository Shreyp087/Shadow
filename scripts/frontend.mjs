import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";

import { assertPortAvailable } from "./port-check.mjs";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const rootDirectory = resolve(scriptDirectory, "..");
const frontendDirectory = resolve(rootDirectory, "frontend");
const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";

const backendOnlyEnvironmentVariables = [
  "APP_NAME",
  "DATABASE_URL",
  "DOCKER_DATABASE_URL",
  "FRONTEND_ORIGIN",
  "ENCRYPTION_KEY",
  "ENCRYPTION_KEY_PREVIOUS",
  "OPENAI_API_KEY",
  "OPENAI_ATTACKER_MODEL",
  "OPENAI_MUTATION_MODEL",
  "OPENAI_SCORER_MODEL",
  "CLERK_JWT_KEY",
  "CLERK_ISSUER",
  "CLERK_JWKS_URL",
  "CLERK_FRONTEND_API_URL",
  "CLERK_AUTHORIZED_PARTIES",
  "ALLOW_INSECURE_TARGET_ENDPOINTS",
  "ALLOW_PRIVATE_TARGET_ENDPOINTS",
  "SHADOWLEDGER_BEARER_TOKEN"
];

const actions = {
  dev: ["run", "dev"],
  test: ["run", "test"],
  lint: ["run", "lint"],
  typecheck: ["run", "typecheck"],
  build: ["run", "build"]
};

const action = process.argv[2];
const args = actions[action];

if (!args) {
  console.error(`Unknown frontend action: ${action ?? "<missing>"}`);
  console.error(`Expected one of: ${Object.keys(actions).join(", ")}`);
  process.exit(2);
}

if (action === "dev") {
  try {
    await assertPortAvailable({ host: "localhost", port: 4200, service: "frontend" });
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(1);
  }
}

const supportsProcessGroups = process.platform !== "win32";
const child = spawn(npmCommand, args, {
  cwd: frontendDirectory,
  detached: supportsProcessGroups,
  env: buildFrontendEnvironment(process.env),
  shell: process.platform === "win32",
  stdio: "inherit"
});

function buildFrontendEnvironment(sourceEnvironment) {
  const frontendEnvironment = { ...sourceEnvironment };

  for (const variableName of backendOnlyEnvironmentVariables) {
    delete frontendEnvironment[variableName];
  }

  return frontendEnvironment;
}

let forwardedSignal = null;
let shutdownEscalationScheduled = false;

const signalChildProcessTree = (signal) => {
  if (!child.pid) {
    return false;
  }

  try {
    if (supportsProcessGroups) {
      process.kill(-child.pid, signal);
    } else {
      if (child.exitCode !== null || child.signalCode !== null) {
        return false;
      }
      child.kill(signal);
    }
    return true;
  } catch (error) {
    const errorCode = error && typeof error === "object" && "code" in error ? error.code : null;
    if (errorCode !== "ESRCH") {
      console.error(`Unable to stop the frontend process tree: ${String(error)}`);
    }
    return false;
  }
};

const processTreeIsRunning = () => {
  if (!supportsProcessGroups || !child.pid) {
    return child.exitCode === null && child.signalCode === null;
  }

  try {
    process.kill(-child.pid, 0);
    return true;
  } catch (error) {
    const errorCode = error && typeof error === "object" && "code" in error ? error.code : null;
    return errorCode !== "ESRCH";
  }
};

const scheduleShutdownEscalation = () => {
  if (!supportsProcessGroups || shutdownEscalationScheduled) {
    return;
  }

  shutdownEscalationScheduled = true;
  const gracefulTimer = setTimeout(() => signalChildProcessTree("SIGTERM"), 250);
  const forceTimer = setTimeout(() => signalChildProcessTree("SIGKILL"), 2000);
  const stopMonitoringTimer = setTimeout(() => clearInterval(monitor), 2500);
  const monitor = setInterval(() => {
    if (!processTreeIsRunning()) {
      clearTimeout(gracefulTimer);
      clearTimeout(forceTimer);
      clearTimeout(stopMonitoringTimer);
      clearInterval(monitor);
    }
  }, 50);
};

const forwardSignal = (signal) => {
  forwardedSignal ??= signal;
  signalChildProcessTree(signal);
  scheduleShutdownEscalation();
};
const onSigint = () => forwardSignal("SIGINT");
const onSigterm = () => forwardSignal("SIGTERM");

process.once("SIGINT", onSigint);
process.once("SIGTERM", onSigterm);

child.once("error", (error) => {
  console.error(error.message);
  process.exitCode = 1;
});
child.once("exit", (code, signal) => {
  process.removeListener("SIGINT", onSigint);
  process.removeListener("SIGTERM", onSigterm);
  process.exitCode = code ?? (signal && forwardedSignal ? 0 : 1);
});
