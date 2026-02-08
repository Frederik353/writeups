#!/usr/bin/env node
// early-access.mjs — Encrypts/decrypts markdown for early-access posts.
//
// Usage:
//   EARLY_ACCESS_PASSWORD=... node scripts/early-access.mjs encrypt   (local, before commit)
//   EARLY_ACCESS_PASSWORD=... node scripts/early-access.mjs decrypt   (CI, before hugo build)
//
// encrypt: future-dated releaseDate posts get body+metadata encrypted in-place
// decrypt: past-dated releaseDate posts get restored to plaintext in-place

import { readFileSync, writeFileSync, readdirSync, existsSync } from "fs";
import { join } from "path";
import { randomBytes, createHash, pbkdf2Sync, createCipheriv, createDecipheriv } from "crypto";

// Load .env file if present (no npm dependencies)
const envPath = join(process.cwd(), ".env");
if (existsSync(envPath)) {
  for (const line of readFileSync(envPath, "utf8").split("\n")) {
    const m = line.match(/^\s*([A-Z_]+)\s*=\s*(.+?)\s*$/);
    if (m && !process.env[m[1]]) process.env[m[1]] = m[2];
  }
}

const PASSWORD = process.env.EARLY_ACCESS_PASSWORD;
if (!PASSWORD) {
  process.exit(0);
}

const MODE = process.argv[2] || "encrypt";
if (MODE !== "encrypt" && MODE !== "decrypt" && MODE !== "decrypt-all") {
  console.error("[early-access] Usage: node early-access.mjs [encrypt|decrypt|decrypt-all]");
  process.exit(1);
}

const CONTENT_DIR = join(process.cwd(), "content");
const PBKDF2_ITERATIONS = 600_000;
const SALT_LEN = 16;
const IV_LEN = 12;

const passwordHash = createHash("sha256").update(PASSWORD).digest("hex");

// Fields to strip from public frontmatter and hide inside the encrypted blob
// ctfs is kept — it's not sensitive (already visible in the URL) and needed for Hugo taxonomy listing
const SENSITIVE_FIELDS = ["tags", "topics", "summary"];

function findMarkdownFiles(dir) {
  const results = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) {
      results.push(...findMarkdownFiles(full));
    } else if (entry.name.endsWith(".md")) {
      results.push(full);
    }
  }
  return results;
}

function parseFrontmatter(content) {
  const match = content.match(/^---\n([\s\S]*?)\n---\n([\s\S]*)$/);
  if (!match) return null;
  return { raw: match[1], body: match[2] };
}

function getReleaseDate(frontmatterRaw) {
  const match = frontmatterRaw.match(/^releaseDate:\s*["']?(\d{4}-\d{2}-\d{2})["']?\s*$/m);
  if (!match) return null;
  return new Date(match[1] + "T00:00:00Z");
}

function isAlreadyEncrypted(body) {
  return /\{\{<\s*encrypted\s/.test(body);
}

// ── Encryption ──

function encryptString(plaintext) {
  const salt = randomBytes(SALT_LEN);
  const iv = randomBytes(IV_LEN);
  const key = pbkdf2Sync(PASSWORD, salt, PBKDF2_ITERATIONS, 32, "sha256");
  const cipher = createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const authTag = cipher.getAuthTag();
  return Buffer.concat([salt, iv, encrypted, authTag]).toString("base64");
}

function extractAndStripFields(frontmatterRaw) {
  const extracted = {};
  let fm = frontmatterRaw;

  for (const field of SENSITIVE_FIELDS) {
    const re = new RegExp(`^${field}:\\s*(.+)$`, "m");
    const match = fm.match(re);
    if (match) {
      extracted[field] = match[1].trim();
      fm = fm.replace(new RegExp(`^${field}:.*\\n?`, "m"), "");
    }
  }

  return { strippedFm: fm, extracted };
}

function encryptFile(filepath) {
  const content = readFileSync(filepath, "utf8");
  const parsed = parseFrontmatter(content);
  if (!parsed) return false;

  const releaseDate = getReleaseDate(parsed.raw);
  if (!releaseDate) return false;

  const now = new Date();
  if (releaseDate <= now) {
    return false;
  }

  if (isAlreadyEncrypted(parsed.body)) {
    return false;
  }

  // Warn about Hugo shortcodes
  const shortcodePattern = /\{\{[<|%]\s*\w+/g;
  const shortcodes = parsed.body.match(shortcodePattern);
  if (shortcodes) {
    const unique = [...new Set(shortcodes)];
    console.warn(
      `[early-access] WARNING: Shortcodes in ${filepath}: ${unique.join(", ")}. ` +
      `These won't render after client-side decryption.`
    );
  }

  // Extract sensitive fields
  const { strippedFm, extracted } = extractAndStripFields(parsed.raw);

  // Build metadata block inside the encrypted blob
  let metaBlock = "";
  for (const [field, value] of Object.entries(extracted)) {
    metaBlock += `<!--meta:${field}:${value}-->\n`;
  }

  const encryptedData = encryptString(metaBlock + parsed.body);

  // Build sanitized frontmatter
  let fm = strippedFm;
  if (!/^showTableOfContents:/m.test(fm)) fm += "\nshowTableOfContents: false";
  if (!/^excludeFromSearch:/m.test(fm)) fm += "\nexcludeFromSearch: true";
  // Replace summary so listings don't render the encrypted shortcode
  fm = fm.replace(/^summary:.*\n?/m, "");
  fm += '\nsummary: "Early access — password required"';

  const newContent =
    `---\n${fm}\n---\n\n{{< encrypted data="${encryptedData}" hash="${passwordHash}" >}}\n`;

  writeFileSync(filepath, newContent, "utf8");
  console.log(`[early-access] ENCRYPTED: ${filepath}`);
  return true;
}

// ── Decryption ──

function decryptString(b64) {
  const raw = Buffer.from(b64, "base64");
  const salt = raw.slice(0, SALT_LEN);
  const iv = raw.slice(SALT_LEN, SALT_LEN + IV_LEN);
  const authTag = raw.slice(raw.length - 16);
  const ciphertext = raw.slice(SALT_LEN + IV_LEN, raw.length - 16);
  const key = pbkdf2Sync(PASSWORD, salt, PBKDF2_ITERATIONS, 32, "sha256");
  const decipher = createDecipheriv("aes-256-gcm", key, iv);
  decipher.setAuthTag(authTag);
  return decipher.update(ciphertext, null, "utf8") + decipher.final("utf8");
}

function decryptFile(filepath) {
  const content = readFileSync(filepath, "utf8");
  const parsed = parseFrontmatter(content);
  if (!parsed) return false;

  const releaseDate = getReleaseDate(parsed.raw);
  if (!releaseDate) return false;

  if (MODE !== "decrypt-all") {
    const now = new Date();
    if (releaseDate > now) {
      return false; // still in the future, keep encrypted
    }
  }

  if (!isAlreadyEncrypted(parsed.body)) {
    return false; // already plaintext
  }

  // Extract encrypted data from shortcode
  const scMatch = parsed.body.match(/\{\{<\s*encrypted\s+data="([^"]+)"\s+hash="[^"]+"\s*>\}\}/);
  if (!scMatch) return false;

  const plaintext = decryptString(scMatch[1]);

  // Parse metadata comments from the decrypted content
  const metaRegex = /^<!--meta:(\w+):(.+)-->\n?/gm;
  let restoredFields = {};
  let body = plaintext;
  let match;
  while ((match = metaRegex.exec(plaintext)) !== null) {
    restoredFields[match[1]] = match[2];
  }
  body = body.replace(/<!--meta:\w+:.+-->\n?/g, "");

  // Rebuild frontmatter with restored fields
  let fm = parsed.raw;

  // Remove encryption-only fields
  fm = fm.replace(/^showTableOfContents:\s*false\n?/m, "");
  fm = fm.replace(/^excludeFromSearch:\s*true\n?/m, "");

  // Restore sensitive fields before the last line (draft/difficulty)
  for (const [field, value] of Object.entries(restoredFields)) {
    if (!new RegExp(`^${field}:`, "m").test(fm)) {
      // Insert before releaseDate line
      fm = fm.replace(/^(releaseDate:.*$)/m, `${field}: ${value}\n$1`);
    }
  }

  // Clean up any trailing whitespace in frontmatter
  fm = fm.replace(/\n{2,}/g, "\n").replace(/\n$/, "");

  const newContent = `---\n${fm}\n---\n${body}`;

  writeFileSync(filepath, newContent, "utf8");
  console.log(`[early-access] DECRYPTED: ${filepath}`);
  return true;
}

// ── Main ──

const files = findMarkdownFiles(CONTENT_DIR);
let count = 0;

for (const filepath of files) {
  if (MODE === "encrypt") {
    if (encryptFile(filepath)) count++;
  } else if (MODE === "decrypt" || MODE === "decrypt-all") {
    if (decryptFile(filepath)) count++;
  }
}

console.log(`[early-access] Done. ${MODE === "encrypt" ? "Encrypted" : "Decrypted"} ${count} file(s).`);
