import { randomBytes } from "node:crypto";
import { chmodSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { spawn, spawnSync } from "node:child_process";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const rootDirectory = resolve(scriptDirectory, "..");
const backendDirectory = join(rootDirectory, "backend");
const frontendDirectory = join(rootDirectory, "frontend");
const rootEnvPath = join(rootDirectory, ".env");
const rootEnvExamplePath = join(rootDirectory, ".env.example");
const localEnvironmentPaths = [
  rootEnvPath,
  join(backendDirectory, ".env"),
  join(frontendDirectory, ".env.local")
];
const venvDirectory = join(backendDirectory, ".venv");
const venvPython = join(
  venvDirectory,
  process.platform === "win32" ? "Scripts/python.exe" : "bin/python"
);
const npmCommand = process.platform === "win32" ? "npm.cmd" : "npm";

const flags = new Set(process.argv.slice(2));
const knownFlags = new Set(["--backend-only", "--frontend-only"]);
const unknownFlags = [...flags].filter((flag) => !knownFlags.has(flag));

if (unknownFlags.length > 0 || (flags.has("--backend-only") && flags.has("--frontend-only"))) {
  console.error("Usage: node scripts/setup.mjs [--backend-only | --frontend-only]");
  process.exit(2);
}

const installBackend = !flags.has("--frontend-only");
const installFrontend = !flags.has("--backend-only");

try {
  assertNodeVersion();
  const python = installBackend ? findSupportedPython() : null;

  ensureRootEnvironment();

  if (installFrontend) {
    await run(npmCommand, ["ci"], frontendDirectory, "Installing frontend dependencies");
  }

  if (installBackend && python) {
    await ensureBackendEnvironment(python);
  }

  console.log("\nShadowLedger setup complete.");
  console.log("Ensure PostgreSQL is running and DATABASE_URL in .env is reachable.");
  console.log("Then start the application with: npm run dev");
} catch (error) {
  console.error(`\nSetup failed: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
}

function assertNodeVersion() {
  const [major, minor] = process.versions.node.split(".").map(Number);
  if (major < 20 || (major === 20 && minor < 6)) {
    throw new Error(`Node.js 20.6 or newer is required; found ${process.versions.node}.`);
  }
}

function ensureRootEnvironment() {
  if (existsSync(rootEnvPath)) {
    protectLocalEnvironmentFiles();
    const currentEnvironment = readFileSync(rootEnvPath, "utf8");
    if (/^DATABASE_URL=.*@(postgres|db):/m.test(currentEnvironment)) {
      console.warn(
        "Warning: .env still uses a Docker database hostname. Use localhost, 127.0.0.1, or a managed PostgreSQL host for npm development."
      );
    }
    console.log("Using existing .env (left unchanged).");
    return;
  }

  if (!existsSync(rootEnvExamplePath)) {
    throw new Error(".env.example is missing.");
  }

  const encryptionKey = `${randomBytes(32).toString("base64url")}=`;
  const environment = readFileSync(rootEnvExamplePath, "utf8").replace(
    /^ENCRYPTION_KEY=.*$/m,
    `ENCRYPTION_KEY=${encryptionKey}`
  );

  writeFileSync(rootEnvPath, environment, { encoding: "utf8", mode: 0o600, flag: "wx" });
  protectLocalEnvironmentFiles();
  console.log("Created .env with a generated Fernet encryption key.");
}

function protectLocalEnvironmentFiles() {
  if (process.platform === "win32") {
    return;
  }

  for (const environmentPath of localEnvironmentPaths) {
    if (existsSync(environmentPath)) {
      chmodSync(environmentPath, 0o600);
    }
  }
}

function findSupportedPython() {
  const candidates = [];
  const configuredPython = process.env.SHADOWLEDGER_PYTHON?.trim();
  if (configuredPython) {
    candidates.push({ command: configuredPython, args: [] });
  }

  if (existsSync(venvPython)) {
    candidates.push({ command: venvPython, args: [] });
  }

  if (process.platform === "darwin") {
    candidates.push(
      { command: "/opt/homebrew/bin/python3.13", args: [] },
      { command: "/opt/homebrew/bin/python3.12", args: [] },
      { command: "/opt/homebrew/bin/python3.11", args: [] },
      { command: "/usr/local/bin/python3.13", args: [] },
      { command: "/usr/local/bin/python3.12", args: [] },
      { command: "/usr/local/bin/python3.11", args: [] }
    );
  }

  candidates.push(
    { command: "python3.13", args: [] },
    { command: "python3.12", args: [] },
    { command: "python3.11", args: [] },
    { command: "python3", args: [] },
    { command: "python", args: [] },
    { command: "py", args: ["-3.11"] }
  );

  for (const candidate of candidates) {
    const version = probePython(candidate.command, candidate.args);
    if (version && isSupportedPython(version)) {
      console.log(`Using Python ${version.join(".")} from ${candidate.command}.`);
      return candidate;
    }
  }

  throw new Error(
    "Python 3.11 or newer was not found. Install Python 3.11+, or set SHADOWLEDGER_PYTHON to its executable path."
  );
}

function probePython(command, prefixArgs = []) {
  const result = spawnSync(
    command,
    [
      ...prefixArgs,
      "-c",
      "import sys; print('.'.join(str(part) for part in sys.version_info[:3]))"
    ],
    { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] }
  );

  if (result.status !== 0) {
    return null;
  }

  const version = result.stdout.trim().split(".").map(Number);
  return version.length === 3 && version.every(Number.isInteger) ? version : null;
}

function isSupportedPython([major, minor]) {
  return major === 3 && minor >= 11;
}

async function ensureBackendEnvironment(python) {
  if (!existsSync(venvPython)) {
    await run(
      python.command,
      [...python.args, "-m", "venv", venvDirectory],
      rootDirectory,
      "Creating backend virtual environment"
    );
  } else {
    const version = probePython(venvPython);
    if (!version || !isSupportedPython(version)) {
      throw new Error(
        "Existing backend/.venv is not using Python 3.11+. Remove that virtual environment, then run npm run setup:backend again."
      );
    }
    console.log(`Using existing backend virtual environment (Python ${version.join(".")}).`);
  }

  await run(
    venvPython,
    ["-m", "pip", "install", "-r", "requirements.txt"],
    backendDirectory,
    "Installing backend dependencies"
  );
}

function run(command, args, cwd, label) {
  console.log(`\n${label}...`);

  return new Promise((resolvePromise, rejectPromise) => {
    const child = spawn(command, args, {
      cwd,
      env: { ...process.env, PYTHONUNBUFFERED: "1" },
      shell: process.platform === "win32" && command === npmCommand,
      stdio: "inherit"
    });

    child.once("error", rejectPromise);
    child.once("exit", (code, signal) => {
      if (code === 0) {
        resolvePromise();
        return;
      }

      rejectPromise(
        new Error(`${label} exited with ${signal ? `signal ${signal}` : `code ${code ?? 1}`}.`)
      );
    });
  });
}
