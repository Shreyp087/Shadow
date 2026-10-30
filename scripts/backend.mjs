import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";

import { assertPortAvailable } from "./port-check.mjs";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const rootDirectory = resolve(scriptDirectory, "..");
const backendDirectory = join(rootDirectory, "backend");
const python = join(
  backendDirectory,
  ".venv",
  process.platform === "win32" ? "Scripts/python.exe" : "bin/python"
);
const frontendOnlyEnvironmentVariables = [
  "NEXT_PUBLIC_API_URL",
  "RAILWAY_BACKEND_URL",
  "NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY",
  "CLERK_SECRET_KEY"
];

const action = process.argv[2];
const actionArgs = process.argv.slice(3);
const supportedActions = new Set([
  "dev",
  "prepare",
  "migrate",
  "seed",
  "test",
  "check-api",
  "check-data",
  "rotate-target-keys",
  "verify-ledger"
]);

if (!supportedActions.has(action)) {
  console.error(`Unknown backend action: ${action ?? "<missing>"}`);
  console.error(`Expected one of: ${[...supportedActions].join(", ")}`);
  process.exit(2);
}

if (action === "verify-ledger" && actionArgs.length !== 1) {
  console.error("Usage: npm run verify:ledger -- <attack-run-id>");
  process.exit(2);
}

if (!existsSync(python)) {
  console.error("backend/.venv is missing. Run npm run setup first.");
  process.exit(1);
}

try {
  const exitCode = await runAction(action);
  process.exitCode = exitCode;
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  process.exitCode = 1;
}

async function runAction(selectedAction) {
  switch (selectedAction) {
    case "dev": {
      await assertPortAvailable({ host: "127.0.0.1", port: 8000, service: "API" });
      const preparationCode = await prepareDatabase();
      if (preparationCode !== 0) {
        printDatabaseHint();
        return preparationCode;
      }
      return runPython(
        ["-m", "uvicorn", "app.main:app", "--reload", "--host", "127.0.0.1", "--port", "8000"],
        backendDirectory
      );
    }
    case "prepare": {
      const code = await prepareDatabase();
      if (code !== 0) {
        printDatabaseHint();
      }
      return code;
    }
    case "migrate":
      return runPython(["-m", "alembic", "upgrade", "head"], backendDirectory);
    case "seed":
      return seedDatabase();
    case "test":
      return runPython(
        [
          "-m",
          "pytest",
          "backend/tests",
          "--cov=backend",
          "--cov-report=term-missing",
          "--cov-fail-under=60"
        ],
        rootDirectory
      );
    case "check-api":
      return runPython(["scripts/check_api.py"], backendDirectory);
    case "check-data":
      return runPython(["scripts/check_demo_data.py"], backendDirectory);
    case "rotate-target-keys":
      return runPython(["scripts/rotate_target_keys.py"], backendDirectory);
    case "verify-ledger":
      return runPython(["scripts/verify_ledger.py", ...actionArgs], backendDirectory);
    default:
      return 2;
  }
}

async function prepareDatabase() {
  const migrationCode = await runPython(["-m", "alembic", "upgrade", "head"], backendDirectory);
  return migrationCode === 0 ? seedDatabase() : migrationCode;
}

async function seedDatabase() {
  const vectorsCode = await runPython(["-m", "seeds.run_seeds"], backendDirectory);
  if (vectorsCode !== 0) {
    return vectorsCode;
  }
  return runPython(["-m", "seeds.demo_data"], backendDirectory);
}

function runPython(args, cwd) {
  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(python, args, {
      cwd,
      env: buildBackendEnvironment(process.env),
      stdio: "inherit"
    });

    let forwardedSignal = null;
    const forwardSignal = (signal) => {
      forwardedSignal = signal;
      if (!child.killed) {
        child.kill(signal);
      }
    };
    const onSigint = () => forwardSignal("SIGINT");
    const onSigterm = () => forwardSignal("SIGTERM");

    process.once("SIGINT", onSigint);
    process.once("SIGTERM", onSigterm);

    const cleanUp = () => {
      process.removeListener("SIGINT", onSigint);
      process.removeListener("SIGTERM", onSigterm);
    };

    child.once("error", (error) => {
      cleanUp();
      rejectPromise(error);
    });
    child.once("exit", (code, signal) => {
      cleanUp();
      resolvePromise(code ?? (signal && signal === forwardedSignal ? 0 : 1));
    });
  });
}

function buildBackendEnvironment(sourceEnvironment) {
  const backendEnvironment = { ...sourceEnvironment, PYTHONUNBUFFERED: "1" };

  for (const variableName of frontendOnlyEnvironmentVariables) {
    delete backendEnvironment[variableName];
  }

  return backendEnvironment;
}

function printDatabaseHint() {
  console.error(
    "Database preparation failed. Ensure PostgreSQL is running and DATABASE_URL in .env points to a reachable database."
  );
}
