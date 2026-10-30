import assert from "node:assert/strict";
import { createServer } from "node:net";
import test from "node:test";

import { assertPortAvailable } from "./port-check.mjs";

test("accepts an available port", async () => {
  const port = await reserveThenReleasePort();

  await assert.doesNotReject(
    assertPortAvailable({ host: "127.0.0.1", port, service: "test service" })
  );
});

test("rejects an occupied port with an actionable message", async (context) => {
  const server = createServer();
  await listen(server);
  context.after(() => close(server));
  const address = server.address();

  assert(address && typeof address === "object");
  await assert.rejects(
    assertPortAvailable({ host: "127.0.0.1", port: address.port, service: "test service" }),
    (error) => {
      assert.match(error.message, /Cannot start ShadowLedger test service/);
      assert.match(error.message, /already in use/);
      assert.match(error.message, new RegExp(`lsof .*${address.port}`));
      return true;
    }
  );
});

async function reserveThenReleasePort() {
  const server = createServer();
  await listen(server);
  const address = server.address();
  assert(address && typeof address === "object");
  await close(server);
  return address.port;
}

function listen(server) {
  return new Promise((resolvePromise, rejectPromise) => {
    server.once("error", rejectPromise);
    server.listen({ host: "127.0.0.1", port: 0, exclusive: true }, resolvePromise);
  });
}

function close(server) {
  return new Promise((resolvePromise, rejectPromise) => {
    server.close((error) => (error ? rejectPromise(error) : resolvePromise()));
  });
}
