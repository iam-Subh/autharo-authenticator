"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { webcrypto } = require("node:crypto");

const elements = new Map();
function element(id) {
  if (!elements.has(id)) {
    elements.set(id, {
      id,
      value: "",
      textContent: "",
      classList: { add() {}, remove() {}, toggle() {} },
      addEventListener() {},
      replaceChildren() {},
    });
  }
  return elements.get(id);
}

const context = vm.createContext({
  console,
  URL,
  TextEncoder,
  TextDecoder,
  Uint8Array,
  BigInt,
  Response,
  crypto: webcrypto,
  atob: (value) => Buffer.from(value, "base64").toString("binary"),
  btoa: (value) => Buffer.from(value, "binary").toString("base64"),
  document: {
    getElementById: element,
    createElement: () => element(Symbol("element")),
  },
  chrome: {
    storage: { local: { get: async () => ({}), set: async () => {}, remove: async () => {} } },
    permissions: { request: async () => false },
  },
  navigator: { clipboard: { writeText: async () => {}, readText: async () => "" } },
  setInterval: () => 0,
  setTimeout,
  clearTimeout,
  confirm: () => false,
});

const source = fs.readFileSync(path.join(__dirname, "popup.js"), "utf8");
vm.runInContext(source, context);

function evaluate(script) {
  return vm.runInContext(script, context);
}

evaluate(`validateEntry({type:"totp", secret:"JBSWY3DPEHPK3PXP", account:"person@example.com"})`);
assert.throws(
  () => evaluate(`validateEntry({type:"totp", secret:"JBSWY3DPEHPK3PXP", account:""})`),
  /fields are invalid/,
);
assert.throws(
  () => evaluate(`validateEntry({type:"hotp", secret:"JBSWY3DPEHPK3PXP", account:"a", counter:"18446744073709551616"})`),
  /counter is invalid/,
);

(async () => {
  await assert.rejects(
    evaluate(`importShare("http://example.test/share#AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")`),
    /must use HTTPS/,
  );
  assert.equal(
    await evaluate(`readLimitedText(new Response("small"), 10)`),
    "small",
  );
  await assert.rejects(
    evaluate(`readLimitedText(new Response("this is too large"), 5)`),
    /too large/,
  );
  console.log("browser extension security tests passed");
})().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
