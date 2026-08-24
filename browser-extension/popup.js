"use strict";

const encoder = new TextEncoder();
const decoder = new TextDecoder();
const LOCAL_AAD = encoder.encode("authcore-browser-v1");
const SHARE_AAD = encoder.encode("authcore-share/v1");
const PBKDF2_ITERATIONS = 600000;

let entries = [];
let localKey = null;
let localSalt = null;
let rendering = false;

const $ = (id) => document.getElementById(id);

function show(section) {
  for (const id of ["setup", "unlock", "vault"]) $(id).classList.add("hidden");
  $(section).classList.remove("hidden");
  $("lock").classList.toggle("hidden", section !== "vault");
  clearMessage();
}

function message(text) {
  $("message").textContent = text;
  $("message").classList.remove("hidden");
}

function clearMessage() {
  $("message").textContent = "";
  $("message").classList.add("hidden");
}

function b64decode(value) {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((value.length + 3) % 4);
  const binary = atob(padded);
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

function b64encode(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function deriveLocalKey(password, salt) {
  const material = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", hash: "SHA-256", salt, iterations: PBKDF2_ITERATIONS },
    material,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

async function saveVault() {
  const nonce = crypto.getRandomValues(new Uint8Array(12));
  const plaintext = encoder.encode(JSON.stringify(entries));
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: nonce, additionalData: LOCAL_AAD },
    localKey,
    plaintext,
  );
  await chrome.storage.local.set({
    vault: {
      version: 1,
      kdf: "PBKDF2-SHA256",
      iterations: PBKDF2_ITERATIONS,
      salt: b64encode(localSalt),
      algorithm: "AES-256-GCM",
      nonce: b64encode(nonce),
      data: b64encode(new Uint8Array(ciphertext)),
    },
  });
}

async function unlock() {
  clearMessage();
  const password = $("unlock-password").value;
  const stored = (await chrome.storage.local.get("vault")).vault;
  try {
    localSalt = b64decode(stored.salt);
    localKey = await deriveLocalKey(password, localSalt);
    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: b64decode(stored.nonce), additionalData: LOCAL_AAD },
      localKey,
      b64decode(stored.data),
    );
    entries = JSON.parse(decoder.decode(plaintext));
    $("unlock-password").value = "";
    show("vault");
    await renderEntries();
  } catch (_) {
    localKey = null;
    entries = [];
    message("The password is not correct, or the browser vault is damaged.");
  }
}

async function importShare(linkText) {
  const url = new URL(linkText.trim());
  if (!url.hash || !/^https?:$/.test(url.protocol)) throw new Error("The share link is not valid.");
  const permitted = await chrome.permissions.request({ origins: [`${url.origin}/*`] });
  if (!permitted) throw new Error("Permission to contact the share server was not granted.");
  const shareKey = b64decode(url.hash.slice(1));
  if (shareKey.length !== 32) throw new Error("The share link has an invalid key.");
  url.hash = "";
  const response = await fetch(url.toString(), { credentials: "omit", cache: "no-store" });
  const body = await response.json().catch(() => null);
  if (!response.ok) throw new Error(body?.message || `The share server returned HTTP ${response.status}.`);
  const envelope = JSON.parse(body.payload);
  if (envelope.format !== "authcore-share" || envelope.version !== 1 || envelope.algorithm !== "AES-256-GCM") {
    throw new Error("The shared account uses an unsupported format.");
  }
  const key = await crypto.subtle.importKey("raw", shareKey, "AES-GCM", false, ["decrypt"]);
  let plaintext;
  try {
    plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: b64decode(envelope.nonce), additionalData: SHARE_AAD },
      key,
      b64decode(envelope.data),
    );
  } catch (_) {
    throw new Error("The share is damaged or the link has the wrong key.");
  }
  const imported = JSON.parse(decoder.decode(plaintext));
  if (!Array.isArray(imported) || imported.length === 0) throw new Error("The share contains no account.");
  for (const entry of imported) validateEntry(entry);
  return imported;
}

function validateEntry(entry) {
  if (!["totp", "hotp", "steam"].includes(entry.type)) throw new Error("The share contains an unsupported entry type.");
  if (typeof entry.secret !== "string" || typeof entry.account !== "string") throw new Error("The shared account is incomplete.");
  base32decode(entry.secret);
}

async function setup() {
  clearMessage();
  const password = $("setup-password").value;
  if (password.length < 10) return message("Use a browser master password with at least 10 characters.");
  if (password !== $("setup-confirm").value) return message("The passwords do not match.");
  try {
    const imported = await importShare($("setup-link").value);
    localSalt = crypto.getRandomValues(new Uint8Array(16));
    localKey = await deriveLocalKey(password, localSalt);
    entries = deduplicate([], imported);
    await saveVault();
    $("setup-password").value = "";
    $("setup-confirm").value = "";
    $("setup-link").value = "";
    show("vault");
    await renderEntries();
  } catch (error) {
    message(error.message || String(error));
  }
}

function deduplicate(existing, imported) {
  const result = [...existing];
  const secrets = new Set(existing.map((entry) => entry.secret.replace(/\s/g, "").toUpperCase()));
  for (const entry of imported) {
    const secret = entry.secret.replace(/\s/g, "").toUpperCase();
    if (!secrets.has(secret)) {
      secrets.add(secret);
      result.push(entry);
    }
  }
  return result;
}

async function addShare() {
  clearMessage();
  try {
    const imported = await importShare($("add-link").value);
    entries = deduplicate(entries, imported);
    await saveVault();
    $("add-link").value = "";
    await renderEntries();
  } catch (error) {
    message(error.message || String(error));
  }
}

function base32decode(text) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const clean = text.toUpperCase().replace(/[\s=-]/g, "");
  let bits = 0;
  let value = 0;
  const output = [];
  for (const character of clean) {
    const index = alphabet.indexOf(character);
    if (index < 0) throw new Error("An account has an invalid Base32 secret.");
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      output.push((value >>> (bits - 8)) & 255);
      bits -= 8;
    }
  }
  if (output.length === 0) throw new Error("An account has an empty secret.");
  return new Uint8Array(output);
}

async function otp(entry) {
  const period = Number(entry.period || 30);
  const counter = entry.type === "hotp"
    ? BigInt(entry.counter || 0)
    : BigInt(Math.floor(Date.now() / 1000 / period));
  const bytes = new Uint8Array(8);
  let moving = counter;
  for (let index = 7; index >= 0; index--) {
    bytes[index] = Number(moving & 255n);
    moving >>= 8n;
  }
  const hash = { SHA1: "SHA-1", SHA256: "SHA-256", SHA512: "SHA-512" }[entry.algorithm || "SHA1"];
  if (!hash) throw new Error("Unsupported hash algorithm.");
  const hmacKey = await crypto.subtle.importKey(
    "raw",
    base32decode(entry.secret),
    { name: "HMAC", hash },
    false,
    ["sign"],
  );
  const digest = new Uint8Array(await crypto.subtle.sign("HMAC", hmacKey, bytes));
  const offset = digest[digest.length - 1] & 15;
  let value = ((digest[offset] & 127) << 24) |
    (digest[offset + 1] << 16) |
    (digest[offset + 2] << 8) |
    digest[offset + 3];
  value >>>= 0;
  if (entry.type === "steam") {
    const alphabet = "23456789BCDFGHJKMNPQRTVWXY";
    let code = "";
    for (let index = 0; index < 5; index++) {
      code += alphabet[value % alphabet.length];
      value = Math.floor(value / alphabet.length);
    }
    return code;
  }
  const digits = Number(entry.digits || 6);
  return String(value % (10 ** digits)).padStart(digits, "0");
}

async function renderEntries() {
  if (rendering || !localKey) return;
  rendering = true;
  try {
    const root = $("entries");
    root.replaceChildren();
    for (const [index, entry] of entries.entries()) {
      const code = await otp(entry);
      const container = document.createElement("div");
      container.className = "entry";
      const name = document.createElement("div");
      name.className = "entry-name";
      name.textContent = entry.issuer ? `${entry.issuer} — ${entry.account}` : entry.account;
      const row = document.createElement("div");
      row.className = "entry-row";
      const codeElement = document.createElement("span");
      codeElement.className = "code";
      codeElement.textContent = code;
      const actions = document.createElement("span");
      actions.className = "entry-actions";
      const copy = document.createElement("button");
      copy.type = "button";
      copy.textContent = "Copy";
      copy.addEventListener("click", () => navigator.clipboard.writeText(code));
      actions.append(copy);
      const remove = document.createElement("button");
      remove.type = "button";
      remove.textContent = "Remove";
      remove.addEventListener("click", async () => {
        if (!confirm(`Remove ${entry.issuer || entry.account} from this browser?`)) return;
        entries.splice(index, 1);
        await saveVault();
        await renderEntries();
      });
      actions.append(remove);
      if (entry.type === "hotp") {
        const next = document.createElement("button");
        next.type = "button";
        next.textContent = "Next";
        next.addEventListener("click", async () => {
          entries[index].counter = Number(entry.counter || 0) + 1;
          await saveVault();
          await renderEntries();
        });
        actions.append(next);
      } else {
        const remaining = document.createElement("span");
        remaining.className = "remaining";
        const period = Number(entry.period || 30);
        remaining.textContent = `${period - (Math.floor(Date.now() / 1000) % period)}s`;
        actions.append(remaining);
      }
      row.append(codeElement, actions);
      container.append(name, row);
      root.append(container);
    }
  } catch (error) {
    message(error.message || String(error));
  } finally {
    rendering = false;
  }
}

function lock() {
  entries = [];
  localKey = null;
  localSalt = null;
  $("entries").replaceChildren();
  show("unlock");
}

async function erase() {
  if (!confirm("Erase all authenticator accounts stored in this browser?")) return;
  await chrome.storage.local.remove("vault");
  entries = [];
  localKey = null;
  localSalt = null;
  show("setup");
}

$("setup-button").addEventListener("click", setup);
$("unlock-button").addEventListener("click", unlock);
$("unlock-password").addEventListener("keydown", (event) => {
  if (event.key === "Enter") unlock();
});
$("add-button").addEventListener("click", addShare);
$("lock").addEventListener("click", lock);
$("erase").addEventListener("click", erase);

chrome.storage.local.get("vault").then(({ vault }) => show(vault ? "unlock" : "setup"));
setInterval(renderEntries, 1000);
