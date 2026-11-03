// Writes the tool list into index.html. In-progress ("wip") links are encrypted with the manager PIN,
// so neither the PIN nor those links appear in the page source.
//   Build:   MANAGER_PIN=xxxx node tools/build.mjs            (reads tools/links.json)
//   Recover: MANAGER_PIN=xxxx node tools/build.mjs decrypt    (writes tools/links.json from index.html)
// tools/links.json is git-ignored. Never commit it or the PIN.
import { readFileSync, writeFileSync } from "node:fs";
const { subtle } = globalThis.crypto;
const ITER = 600000, enc = new TextEncoder(), dec = new TextDecoder();
const b64 = (u) => Buffer.from(u).toString("base64"), unb64 = (s) => new Uint8Array(Buffer.from(s, "base64"));
async function key(secret, salt) {
  const base = await subtle.importKey("raw", enc.encode(secret), "PBKDF2", false, ["deriveKey"]);
  return subtle.deriveKey({ name: "PBKDF2", salt, iterations: ITER, hash: "SHA-256" }, base, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
}
async function seal(obj, secret) {
  const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await subtle.encrypt({ name: "AES-GCM", iv }, await key(secret, salt), enc.encode(JSON.stringify(obj)));
  return { s: b64(salt), i: b64(iv), c: b64(new Uint8Array(ct)) };
}
async function open(box, secret) {
  const pt = await subtle.decrypt({ name: "AES-GCM", iv: unb64(box.i) }, await key(secret, unb64(box.s)), unb64(box.c));
  return JSON.parse(dec.decode(pt));
}
const { MANAGER_PIN } = process.env;
if (!MANAGER_PIN) { console.error("Set MANAGER_PIN"); process.exit(1); }
const html = readFileSync("index.html", "utf8"), re = /\/\*VAULT\*\/[\s\S]*?\/\*END\*\//;
if (process.argv[2] === "decrypt") {
  const vault = JSON.parse(html.match(re)[0].slice(9, -7));
  const tiles = vault.tiles, wip = await open(vault.mgr, MANAGER_PIN);
  writeFileSync("tools/links.json", JSON.stringify(tiles.map((t, n) => (t.url ? t : { ...t, url: wip[n] })), null, 2) + "\n");
  console.log("Wrote tools/links.json");
} else {
  const links = JSON.parse(readFileSync("tools/links.json", "utf8")), wip = {};
  const tiles = links.map((l, n) => { if (l.status === "wip") { wip[n] = l.url; const { url, ...rest } = l; return rest; } return l; });
  const vault = { tiles, mgr: await seal(wip, MANAGER_PIN) };
  writeFileSync("index.html", html.replace(re, "/*VAULT*/" + JSON.stringify(vault) + "/*END*/"));
  console.log("Encrypted", links.length, "tools into index.html");
}
