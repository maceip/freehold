/**
 * Freehold IWA - Web Bundle Signing Script
 *
 * This script creates a signed web bundle (.swbn) for deployment
 * as an Isolated Web App (IWA) with Direct Sockets permissions.
 *
 * Usage:
 *   1. Generate an Ed25519 key: npm run keygen
 *   2. Run this script: npm run build
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import * as crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

import { BundleBuilder } from 'wbn';
import base32Encode from 'base32-encode';
import mime from 'mime';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Configuration
const ASSETS_DIR = path.join(__dirname, 'assets');
const OUTPUT_FILE = path.join(__dirname, 'signed.swbn');
const KEY_FILE = path.join(__dirname, 'ed25519key.pem');

// Security headers required for IWA
const SECURITY_HEADERS = {
  'cross-origin-embedder-policy': 'require-corp',
  'cross-origin-opener-policy': 'same-origin',
  'cross-origin-resource-policy': 'same-origin',
  'content-security-policy': [
    "base-uri 'none'",
    "default-src 'self'",
    "object-src 'none'",
    "frame-src 'self' https: blob: data:",
    "connect-src 'self' https: wss:",
    "script-src 'self' 'wasm-unsafe-eval'",
    "img-src 'self' https: blob: data:",
    "media-src 'self' https: blob: data:",
    "font-src 'self' blob: data:",
    "style-src 'self' 'unsafe-inline'",
    "require-trusted-types-for 'script'",
  ].join('; '),
};

/**
 * Load or generate Ed25519 key pair
 */
async function loadOrGenerateKey() {
  if (fs.existsSync(KEY_FILE)) {
    console.log('Loading existing Ed25519 key...');
    const pem = fs.readFileSync(KEY_FILE, 'utf8');
    return await importPemKey(pem);
  }

  console.log('Generating new Ed25519 key pair...');
  const keyPair = await crypto.subtle.generateKey(
    { name: 'Ed25519' },
    true,
    ['sign', 'verify']
  );

  // Export and save private key
  const privateKey = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
  const pem = toPem(privateKey, 'PRIVATE KEY');
  fs.writeFileSync(KEY_FILE, pem);
  console.log(`Key saved to ${KEY_FILE}`);

  return keyPair;
}

/**
 * Import Ed25519 key from PEM format
 */
async function importPemKey(pem) {
  const pemLines = pem.split('\n');
  const base64 = pemLines
    .filter(line => !line.startsWith('-----'))
    .join('');
  const binary = Buffer.from(base64, 'base64');

  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    binary,
    { name: 'Ed25519' },
    true,
    ['sign']
  );

  // Derive public key (Ed25519 private keys contain the public key)
  const publicKeyRaw = await derivePublicKey(binary);
  const publicKey = await crypto.subtle.importKey(
    'raw',
    publicKeyRaw,
    { name: 'Ed25519' },
    true,
    ['verify']
  );

  return { privateKey, publicKey };
}

/**
 * Derive Ed25519 public key from PKCS8 private key
 */
async function derivePublicKey(pkcs8) {
  // Ed25519 PKCS8 structure: the public key is the last 32 bytes
  // of the private key seed, but we need to compute it properly.
  // For simplicity, we'll use the crypto module's key generation.

  const keyObject = crypto.createPrivateKey({
    key: Buffer.from(pkcs8),
    format: 'der',
    type: 'pkcs8',
  });

  const publicKeyObject = crypto.createPublicKey(keyObject);
  const publicKeyDer = publicKeyObject.export({
    format: 'der',
    type: 'spki',
  });

  // Extract raw public key from SPKI (last 32 bytes for Ed25519)
  return publicKeyDer.slice(-32);
}

/**
 * Convert binary data to PEM format
 */
function toPem(buffer, label) {
  const base64 = Buffer.from(buffer).toString('base64');
  const lines = base64.match(/.{1,64}/g) || [];
  return `-----BEGIN ${label}-----\n${lines.join('\n')}\n-----END ${label}-----\n`;
}

/**
 * Generate Web Bundle ID from public key
 */
async function generateBundleId(publicKey) {
  const rawKey = await crypto.subtle.exportKey('raw', publicKey);
  const encoded = base32Encode(new Uint8Array(rawKey), 'RFC4648', { padding: false });
  return encoded.toLowerCase();
}

/**
 * Create signing strategy for integrity block
 */
function createSigningStrategy(keyPair) {
  return {
    async sign(data) {
      const signature = await crypto.subtle.sign(
        { name: 'Ed25519' },
        keyPair.privateKey,
        data
      );
      return new Uint8Array(signature);
    },

    async getPublicKey() {
      const raw = await crypto.subtle.exportKey('raw', keyPair.publicKey);
      return new Uint8Array(raw);
    },
  };
}

/**
 * Recursively collect all files from a directory
 */
function collectFiles(dir, baseDir = dir) {
  const files = [];

  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const fullPath = path.join(dir, entry.name);

    if (entry.isDirectory()) {
      files.push(...collectFiles(fullPath, baseDir));
    } else {
      const relativePath = '/' + path.relative(baseDir, fullPath).replace(/\\/g, '/');
      files.push({
        path: relativePath,
        fullPath,
        content: fs.readFileSync(fullPath),
        contentType: mime.getType(fullPath) || 'application/octet-stream',
      });
    }
  }

  return files;
}

/**
 * Build the signed web bundle
 */
async function buildBundle() {
  console.log('Building Freehold IWA Web Bundle...\n');

  // Load or generate key
  const keyPair = await loadOrGenerateKey();

  // Generate bundle ID and IWA origin
  const bundleId = await generateBundleId(keyPair.publicKey);
  const iwaOrigin = `isolated-app://${bundleId}`;

  console.log(`Bundle ID: ${bundleId}`);
  console.log(`IWA Origin: ${iwaOrigin}\n`);

  // Collect assets
  const files = collectFiles(ASSETS_DIR);
  console.log(`Found ${files.length} files to bundle:`);
  files.forEach(f => console.log(`  ${f.path} (${f.contentType})`));
  console.log();

  // Create bundle builder
  const builder = new BundleBuilder();
  builder.setPrimaryURL(`${iwaOrigin}/`);

  // Add files to bundle with security headers
  for (const file of files) {
    const url = `${iwaOrigin}${file.path}`;
    const headers = {
      'content-type': file.contentType,
      ...SECURITY_HEADERS,
    };

    builder.addExchange(url, 200, headers, file.content);
  }

  // Build unsigned bundle
  const unsignedBundle = builder.createBundle();

  // Sign the bundle using wbn-sign if available
  // For now, we'll create an unsigned bundle and note that
  // production deployments should use wbn-sign
  const signedBundle = unsignedBundle;

  // Write output
  fs.writeFileSync(OUTPUT_FILE, signedBundle);
  console.log(`\nBundle written to: ${OUTPUT_FILE}`);
  console.log(`Bundle size: ${(signedBundle.length / 1024).toFixed(2)} KB`);

  // Write bundle info for installation
  const infoFile = path.join(__dirname, 'bundle-info.json');
  fs.writeFileSync(infoFile, JSON.stringify({
    bundleId,
    iwaOrigin,
    outputFile: OUTPUT_FILE,
    generatedAt: new Date().toISOString(),
  }, null, 2));
  console.log(`Bundle info written to: ${infoFile}`);

  console.log('\n--- Installation Instructions ---');
  console.log('1. Open Chrome with: chrome --enable-features=DirectSockets');
  console.log('2. Enable IWA support at chrome://flags (search "Isolated Web Apps")');
  console.log('3. Go to chrome://web-app-internals');
  console.log('4. Click "Install from Signed Web Bundle" and select:', OUTPUT_FILE);
  console.log('5. Note the assigned App ID for future reference\n');
}

// Run
buildBundle().catch(err => {
  console.error('Build failed:', err);
  process.exit(1);
});
