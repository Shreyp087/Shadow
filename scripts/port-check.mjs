import { createServer } from "node:net";

export function assertPortAvailable({ host, port, service }) {
  return new Promise((resolvePromise, rejectPromise) => {
    const server = createServer();

    server.once("error", (error) => {
      if (error && typeof error === "object" && "code" in error && error.code === "EADDRINUSE") {
        rejectPromise(new Error(portConflictMessage({ host, port, service })));
        return;
      }

      rejectPromise(error);
    });

    server.listen({ host, port, exclusive: true }, () => {
      server.close((error) => {
        if (error) {
          rejectPromise(error);
          return;
        }
        resolvePromise();
      });
    });
  });
}

function portConflictMessage({ host, port, service }) {
  const inspectCommand =
    process.platform === "win32"
      ? `netstat -ano | findstr :${port}`
      : `lsof -nP -iTCP:${port} -sTCP:LISTEN`;

  return [
    `Cannot start ShadowLedger ${service}: ${host}:${port} is already in use.`,
    "The development stack may already be running. Use the existing instance,",
    "stop it from its original terminal, or inspect the listener with:",
    `  ${inspectCommand}`
  ].join("\n");
}
