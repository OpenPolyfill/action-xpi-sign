#!/usr/bin/env node

// Mozilla Autograph XPI format: signer/xpi/jar.go, x509.go, xpi.go.
import { createHash, createPrivateKey, generateKeyPairSync, randomBytes } from "node:crypto";
import { execFileSync } from "node:child_process";
import {
  existsSync, mkdtempSync, mkdirSync, readFileSync, readdirSync,
  rmSync, writeFileSync, lstatSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, resolve } from "node:path";

const META = "META-INF";
const MANIFEST = `${META}/manifest.mf`;
const SF = `${META}/mozilla.sf`;
const RSA = `${META}/mozilla.rsa`;

function run(command, args, options = {}) {
  return execFileSync(command, args, { ...options, stdio: ["ignore", "pipe", "pipe"] });
}

function safePath(path) {
  return typeof path === "string" && path.length > 0 &&
    !path.includes("\\") && !path.startsWith("/") &&
    !/[\p{Cc}]/u.test(path) &&
    !path.split("/").some((part, index, parts) =>
      (!part && index !== parts.length - 1) || part === "." || part === "..") &&
    Buffer.byteLength(path, "utf8") <= 65535;
}

function isSignature(path) {
  if (!path.toLowerCase().startsWith("meta-inf/")) return false;
  const name = path.slice("META-INF/".length).toLowerCase();
  return name === "manifest.mf" || name.endsWith(".sf") ||
    name.endsWith(".rsa") || name.endsWith(".dsa") ||
    name.startsWith("sig-") || name === "cose.manifest" ||
    name === "cose.sig";
}

function walk(dir, base = dir) {
  const paths = [];
  for (const entry of readdirSync(dir, { withFileTypes: true }).sort((a, b) =>
    a.name.localeCompare(b.name))) {
    const fullPath = join(dir, entry.name);
    if (entry.isDirectory()) paths.push(...walk(fullPath, base));
    else if (entry.isFile() && !lstatSync(fullPath).isSymbolicLink()) {
      paths.push(relative(base, fullPath).replaceAll("\\", "/"));
    } else throw new Error(`Unsupported archive entry: ${entry.name}`);
  }
  return paths;
}

// Port of Autograph's formatFilename: 72 bytes per JAR manifest line,
// with a 65-byte first filename segment and 70-byte continuation segments.
function formatFilename(name) {
  const data = Buffer.from(name, "utf8");
  if (data.length > 65535 || /[\p{Cc}]/u.test(name)) {
    throw new Error(`Invalid JAR filename: ${name}`);
  }
  if (data.length <= 65) return data;
  let header = Buffer.from(data.subarray(0, 65));
  for (let offset = 65; offset < data.length; offset += 70) {
    header = Buffer.concat([header, Buffer.from("\n "), data.subarray(offset, offset + 70)]);
  }
  return header;
}

function b64hash(data, hash) {
  return createHash(hash).update(data).digest("base64");
}

function makeManifest(files, dir) {
  const chunks = [Buffer.from("Manifest-Version: 1.0\n\n")];
  for (const path of files) {
    const body = readFileSync(join(dir, path));
    chunks.push(Buffer.from("Name: "), formatFilename(path));
    chunks.push(Buffer.from(`\nDigest-Algorithms: SHA1 SHA256\n` +
      `SHA1-Digest: ${b64hash(body, "sha1")}\n` +
      `SHA256-Digest: ${b64hash(body, "sha256")}\n\n`));
  }
  return Buffer.concat(chunks);
}

function makeSignatureFile(manifest) {
  return Buffer.from(`Signature-Version: 1.0\n` +
    `SHA1-Digest-Manifest: ${b64hash(manifest, "sha1")}\n` +
    `SHA256-Digest-Manifest: ${b64hash(manifest, "sha256")}\n\n`);
}

function getAddonId(manifest) {
  const id = manifest.browser_specific_settings?.gecko?.id ||
    manifest.applications?.gecko?.id;
  if (typeof id !== "string" || !/^[A-Za-z0-9._@{}-]+$/.test(id)) {
    throw new Error("manifest.json needs a valid browser_specific_settings.gecko.id");
  }
  return id;
}

function createLeaf(id, caKeyPath, caCertPath, workingDir) {
  const caKey = createPrivateKey(readFileSync(caKeyPath));
  const keyOptions = caKey.asymmetricKeyType === "rsa" || caKey.asymmetricKeyType === "rsa-pss"
    ? { type: "rsa", options: { modulusLength: caKey.asymmetricKeyDetails.modulusLength } }
    : caKey.asymmetricKeyType === "ec"
      ? { type: "ec", options: { namedCurve: caKey.asymmetricKeyDetails.namedCurve } }
      : null;
  if (!keyOptions) throw new Error("CA key must be RSA or ECDSA");
  const { privateKey } = generateKeyPairSync(keyOptions.type, keyOptions.options);
  const leafKey = join(workingDir, "leaf-key.pem");
  const csr = join(workingDir, "leaf.csr");
  const certificate = join(workingDir, "leaf.pem");
  const extensions = join(workingDir, "leaf.ext");
  writeFileSync(leafKey, privateKey.export({ type: "pkcs8", format: "pem" }));
  const digest = createHash("sha256").update(id).digest("hex");
  writeFileSync(extensions, [
    "basicConstraints=critical,CA:FALSE",
    "keyUsage=critical,digitalSignature",
    "extendedKeyUsage=codeSigning",
    `subjectAltName=DNS:${digest.slice(0, 32)}.${digest.slice(32)}.addons.mozilla.org`,
    "",
  ].join("\n"));
  run("openssl", ["req", "-new", "-key", leafKey, "-out", csr,
    "-subj", `/C=US/ST=CA/L=Mountain View/O=Addons/OU=Mozilla Extensions/CN=${id}`]);
  run("openssl", ["x509", "-req", "-in", csr, "-CA", caCertPath, "-CAkey", caKeyPath,
    "-set_serial", `0x${randomBytes(16).toString("hex")}`, "-days", "3650",
    "-extfile", extensions, "-out", certificate]);
  return { leafKey, certificate };
}

function main() {
  if (process.argv.length !== 6 && process.argv.length !== 7) {
    throw new Error("Usage: node sign-xpi.mjs unsigned.xpi ca-private-key.pem ca-certificate.pem signed.xpi [expected-addon-id]");
  }
  const [input, caKey, caCert, output] = process.argv.slice(2, 6).map(path => resolve(path));
  const expectedAddonId = process.argv[6];
  if (input === output) throw new Error("Input and output paths must differ");
  if (existsSync(output)) throw new Error(`Output already exists: ${output}`);

  const paths = run("unzip", ["-Z", "-1", input], { encoding: "utf8" })
    .trimEnd().split("\n");
  const seen = new Set();
  for (const name of paths) {
    if (!safePath(name) || seen.has(name)) {
      throw new Error(`Invalid or duplicate ZIP entry: ${name}`);
    }
    seen.add(name);
  }

  const temp = mkdtempSync(join(tmpdir(), "sine-mozilla-xpi-"));
  const unpack = join(temp, "unpacked");
  mkdirSync(unpack);
  try {
    run("unzip", ["-q", input, "-d", unpack]);
    const allFiles = walk(unpack);
    for (const name of allFiles) {
      if (!safePath(name) || !seen.has(name)) {
        throw new Error(`Invalid extracted path: ${name}`);
      }
      if (isSignature(name)) rmSync(join(unpack, name));
    }
    const files = walk(unpack);
    if (!files.length) throw new Error("Empty XPI");
    const addonId = getAddonId(JSON.parse(readFileSync(join(unpack, "manifest.json"), "utf8")));
    if (expectedAddonId && addonId !== expectedAddonId) {
      throw new Error(`Unexpected add-on ID: ${addonId} (expected ${expectedAddonId})`);
    }

    const manifest = makeManifest(files, unpack);
    const signatureFile = makeSignatureFile(manifest);
    const { leafKey, certificate } = createLeaf(addonId, caKey, caCert, temp);
    const sfPath = join(temp, "mozilla.sf");
    const rsaPath = join(temp, "mozilla.rsa");
    writeFileSync(sfPath, signatureFile);
    run("openssl", ["cms", "-sign", "-binary", "-in", sfPath, "-signer", certificate,
      "-inkey", leafKey, "-certfile", caCert, "-outform", "DER", "-out", rsaPath,
      "-md", "sha256"]);
    mkdirSync(join(unpack, META), { recursive: true });
    writeFileSync(join(unpack, MANIFEST), manifest);
    writeFileSync(join(unpack, SF), signatureFile);
    writeFileSync(join(unpack, RSA), readFileSync(rsaPath));
    run("zip", ["-q", "-r", output, "."], { cwd: unpack });
    console.log(`Signed XPI: ${output}`);
    console.log(`Add-on ID: ${addonId}`);
    console.log(`Trusted CA certificate: ${caCert}`);
  } finally {
    rmSync(temp, { recursive: true, force: true });
  }
}

try {
  main();
} catch (error) {
  console.error(error.stderr?.toString().trim() || error.message);
  process.exitCode = 1;
}
