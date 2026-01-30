/**
 * Freehold IWA - Rollup Configuration
 *
 * This configuration uses rollup-plugin-webbundle to create
 * signed web bundles for Isolated Web App deployment.
 *
 * Usage:
 *   1. Create .env file with ED25519KEY
 *   2. Run: npm run bundle
 */

import { nodeResolve } from '@rollup/plugin-node-resolve';
import webbundle from 'rollup-plugin-webbundle';
import * as wbnSign from 'wbn-sign';
import dotenv from 'dotenv';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Load environment variables
dotenv.config({ path: path.join(__dirname, '.env') });

/**
 * Get or generate Ed25519 signing key
 */
async function getSigningKey() {
  // Check for key in environment
  if (process.env.ED25519KEY) {
    console.log('Using ED25519KEY from environment');
    return wbnSign.parsePemKey(process.env.ED25519KEY);
  }

  // Check for key file
  const keyFile = path.join(__dirname, 'ed25519key.pem');
  if (fs.existsSync(keyFile)) {
    console.log('Using key from ed25519key.pem');
    const pem = fs.readFileSync(keyFile, 'utf8');
    return wbnSign.parsePemKey(pem);
  }

  // Generate new key
  console.log('Generating new Ed25519 key...');
  const { exec } = await import('node:child_process');
  const { promisify } = await import('node:util');
  const execAsync = promisify(exec);

  await execAsync(`openssl genpkey -algorithm Ed25519 -out "${keyFile}"`);
  console.log(`Key saved to ${keyFile}`);

  const pem = fs.readFileSync(keyFile, 'utf8');
  return wbnSign.parsePemKey(pem);
}

export default async () => {
  const key = await getSigningKey();

  // Generate IWA origin from public key
  const bundleId = new wbnSign.WebBundleId(key);
  const baseURL = bundleId.serializeWithIsolatedWebAppOrigin();

  console.log('');
  console.log('Web Bundle Configuration:');
  console.log(`  Bundle ID: ${bundleId.serialize()}`);
  console.log(`  Base URL: ${baseURL}`);
  console.log('');

  return {
    input: path.join(__dirname, 'assets', 'script.js'),

    output: {
      dir: path.join(__dirname, 'dist'),
      format: 'esm',
      entryFileNames: '[name].js',
    },

    plugins: [
      nodeResolve({
        browser: true,
      }),

      webbundle({
        // Base URL for the IWA
        baseURL,

        // Static files to include
        static: {
          dir: path.join(__dirname, 'assets'),
        },

        // Output filename
        output: 'freehold.swbn',

        // Integrity block signing configuration
        integrityBlockSign: {
          strategy: new wbnSign.NodeCryptoSigningStrategy(key),
        },

        // Security headers required for IWA
        headerOverride: {
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
        },

        // Primary URL for the bundle
        primaryURL: '/',
      }),
    ],
  };
};
