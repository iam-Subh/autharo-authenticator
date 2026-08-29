"use strict";

const demoSecret = "JBSWY3DPEHPK3PXPGEZDGNBVGY3TQOJQ";
const periodSeconds = 30;

function decodeBase32(value) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  const normalized = value.toUpperCase().replace(/=+$/u, "");
  let bits = 0;
  let bitCount = 0;
  const bytes = [];

  for (const character of normalized) {
    const index = alphabet.indexOf(character);
    if (index < 0) {
      throw new Error("The test setup key is invalid.");
    }
    bits = (bits << 5) | index;
    bitCount += 5;
    if (bitCount >= 8) {
      bitCount -= 8;
      bytes.push((bits >> bitCount) & 0xff);
    }
  }
  return new Uint8Array(bytes);
}

function counterBytes(counter) {
  const bytes = new Uint8Array(8);
  let remaining = BigInt(counter);
  for (let index = 7; index >= 0; index -= 1) {
    bytes[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return bytes;
}

async function totpAt(counter) {
  const key = await crypto.subtle.importKey(
    "raw",
    decodeBase32(demoSecret),
    { name: "HMAC", hash: "SHA-1" },
    false,
    ["sign"],
  );
  const signature = new Uint8Array(
    await crypto.subtle.sign("HMAC", key, counterBytes(counter)),
  );
  const offset = signature[signature.length - 1] & 0x0f;
  const binary =
    ((signature[offset] & 0x7f) << 24) |
    ((signature[offset + 1] & 0xff) << 16) |
    ((signature[offset + 2] & 0xff) << 8) |
    (signature[offset + 3] & 0xff);
  return String(binary % 1_000_000).padStart(6, "0");
}

async function verifyCode(code) {
  const currentCounter = Math.floor(Date.now() / 1000 / periodSeconds);
  const counters = [currentCounter - 1, currentCounter, currentCounter + 1];
  const validCodes = await Promise.all(counters.map(totpAt));
  return validCodes.includes(code);
}

function setResult(message, state) {
  const result = document.querySelector("#verification-result");
  result.textContent = message;
  result.dataset.state = state;
}

function updatePeriod() {
  const elapsed = Math.floor(Date.now() / 1000) % periodSeconds;
  const remaining = periodSeconds - elapsed;
  const label = document.querySelector("#seconds-left");
  const progress = document.querySelector("#period-progress");
  label.textContent = `${remaining} ${remaining === 1 ? "second" : "seconds"}`;
  progress.value = elapsed;
  progress.textContent = `${elapsed} of ${periodSeconds} seconds`;
}

document.querySelector("#otp-code").addEventListener("input", (event) => {
  event.target.value = event.target.value.replace(/\D/gu, "").slice(0, 6);
  setResult("", "idle");
});

document.querySelector("#verify-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const input = document.querySelector("#otp-code");
  const code = input.value.trim();
  if (!/^\d{6}$/u.test(code)) {
    setResult("Enter all six digits.", "error");
    input.focus();
    return;
  }
  try {
    const valid = await verifyCode(code);
    if (valid) {
      setResult("Code verified. Autharo generated the correct code.", "success");
      input.select();
    } else {
      setResult("This code is not valid. Wait for the next code and try again.", "error");
    }
  } catch {
    setResult("Your browser could not verify the code.", "error");
  }
});

document.querySelector("#copy-key").addEventListener("click", async (event) => {
  try {
    await navigator.clipboard.writeText(demoSecret);
    event.currentTarget.textContent = "Copied";
    window.setTimeout(() => {
      event.currentTarget.textContent = "Copy";
    }, 1600);
  } catch {
    setResult("Copy failed. Select and copy the setup key.", "error");
  }
});

updatePeriod();
window.setInterval(updatePeriod, 1000);
