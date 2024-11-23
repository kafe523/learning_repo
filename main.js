"use strict";

/** @type {Array<string>} */
const currentObjectUrl = [];

/** @type {HTMLInputElement} */
const decryptionKeyDomTitle = document.querySelector("#decryption-key-title");

/** @type {HTMLInputElement} */
const decryptionKeyDomContent = document.querySelector(
  "#decryption-key-content",
);

/** @type {HTMLElement} */
const main = document.querySelector("main");

/** @param {ArrayBuffer} buffer  */
function arrayBufferToHex(buffer) {
  const array = Array.from(new Uint8Array(buffer));
  return array.map((b) => b.toString(16).padStart(2, "0")).join("");
}

/** @param {BufferSource} buffer  */
async function sha256BufferDigest(buffer) {
  const msgHashBytes = await window.crypto.subtle.digest("SHA-256", buffer);
  return msgHashBytes;
}

/** @param {string} message */
async function sha256StringDigest(message) {
  const msgEncoded = new TextEncoder().encode(message);
  return await sha256BufferDigest(msgEncoded);
}

/**
 * @param {string} keyString
 * @param {ArrayBufferLike} buffer
 */
async function aesBufferDecryption(keyString, buffer) {
  const key = await window.crypto.subtle.importKey(
    "raw",
    await sha256StringDigest(keyString),
    "AES-CBC",
    true,
    ["decrypt"],
  );
  const iv = buffer.slice(0, 16);
  const content = buffer.slice(16);
  let result = null;

  try {
    result = await window.crypto.subtle.decrypt(
      { name: "AES-CBC", iv },
      key,
      content,
    );
  } catch (e) {
    console.error(e);
  }

  return result;
}

async function getData() {
  /** @type {Array<string>} */
  const result = [];
  let tsvContent = "";
  try {
    const response = await fetch("./dump.tsv");
    const content = await response.text();
    tsvContent = content;
  } catch (error) {
    console.error(error);
    return result;
  }

  for (let line of tsvContent.split("\n")) {
    if (line.length === 0) {
      continue;
    }

    line = line.trim();
    const _r = line.split("\t");
    result.push(_r);
  }

  return result;
}

/** @param {boolean} reset */
async function writeMainContent(isReset = false) {
  if (currentObjectUrl.length > 0) {
    currentObjectUrl.forEach((link) => URL.revokeObjectURL(link));
    currentObjectUrl.length = 0;
  }

  const data = await getData();

  let final = "";

  for (const [n, c, ch, s] of data) {
    let current = "";

    current += "<dl>";

    if (isReset) {
      current += "<dt>encrypted</dt>";
      current += "<dd>encrypted</dd>";
    } else {
      current += "<dt>";

      let title = "Title Decryption Fail";
      const titleBuffer = await aesBufferDecryption(
        decryptionKeyDomTitle.value,
        Uint8Array.from(atob(n), (char) => char.charCodeAt(0)),
      );

      if (titleBuffer !== null) {
        const decodedTitle = new TextDecoder().decode(titleBuffer);
        title = decodedTitle;
      }
      current += title;

      current += "</dt>";

      current += "<dd>";

      const contentBuffer = await aesBufferDecryption(
        [decryptionKeyDomTitle.value, decryptionKeyDomContent.value].join(""),
        Uint8Array.from(atob(c), (char) => char.charCodeAt(0)),
      );

      let content = "encrypted";
      if (contentBuffer !== null) {
        const contentHash = arrayBufferToHex(
          await sha256StringDigest(
            arrayBufferToHex(await sha256BufferDigest(contentBuffer)) + s)
        );

        if (contentHash === ch) {
          const f = new Blob([contentBuffer], {
            type: "application/octet-stream",
          });
          const furl = URL.createObjectURL(f);
          currentObjectUrl.push(furl);

          content = `<a href="${furl}" download="${title}">download</a>`;
        }
      }
      current += content;

      current += "</dd>";
    }

    current += "</dl>";

    final += current;
  }

  main.innerHTML = final;
}

window.addEventListener("DOMContentLoaded", async () => {
  await writeMainContent(true);
});

document.querySelector("#btn-decrypt").addEventListener("click", async () => {
  await writeMainContent();
});

document.querySelector("#btn-reset").addEventListener("click", async () => {
  await writeMainContent(true);
});

document.querySelector("#btn-key-clear-title").addEventListener(
  "click",
  () => {
    decryptionKeyDomTitle.value = "";
  },
);

document.querySelector("#btn-key-clear-content").addEventListener(
  "click",
  () => {
    decryptionKeyDomContent.value = "";
  },
);
