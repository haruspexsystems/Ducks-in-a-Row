import { describe, it, expect } from 'vitest';
import { resolveTemplateKey, type TemplateKeyRequirement } from '@/lib/templateKey';
import {
  buildDirectoryUrl,
  buildEabSnippets,
  CA_BUNDLE_PLACEHOLDER,
  SECRET_PLACEHOLDER,
} from './eabSnippets';

/**
 * The cert-manager manifest the dashboard hands out (issue #439). It used to be
 * an Issuer with no caBundle and no key settings, so against a server whose own
 * certificate chains to an ADCS root it could not connect at all, and on an
 * ECDSA template every order was refused at finalize because cert-manager
 * defaults to RSA 2048.
 */

const DIRECTORY = buildDirectoryUrl('https://ducks.corp.example.com:5001/', 'WebServer');
const KID = '0123456789abcdef0123456789abcdef';
const SECRET = 'c2VjcmV0LXNlY3JldC1zZWNyZXQtc2VjcmV0LXNlY3JldA';

function certManager(key?: TemplateKeyRequirement, secret: string = SECRET): string {
  const snippet = buildEabSnippets(DIRECTORY, KID, secret, key).find((s) => s.id === 'cert-manager');
  if (!snippet) throw new Error('no cert-manager snippet');
  return snippet.text;
}

/** The YAML documents, split on the document marker. */
function documents(text: string): string[] {
  return text.split(/^---$/m);
}

describe('the cert-manager snippet', () => {
  it('points the issuer at the directory and carries the CA bundle placeholder', () => {
    const text = certManager();
    expect(text).toContain(`    server: ${DIRECTORY}\n`);
    expect(text).toContain(`    caBundle: ${CA_BUNDLE_PLACEHOLDER}\n`);
  });

  it('never switches TLS verification off and sets no deprecated MAC algorithm', () => {
    const text = certManager();
    expect(text).not.toMatch(/^\s*skipTLSVerify\s*:/m);
    expect(text).not.toMatch(/keyAlgorithm/);
  });

  it('keeps the secret out of the manifest itself, on the kubectl comment only', () => {
    const lines = certManager()
      .split('\n')
      .filter((line) => line.includes(SECRET));
    expect(lines).toEqual([
      `#   kubectl create secret generic ducks-eab --from-literal=secret='${SECRET}'`,
    ]);
  });

  it('is an Issuer followed by a Certificate that uses it', () => {
    const [issuer, certificate, ...rest] = documents(certManager());
    expect(rest).toEqual([]);
    expect(issuer).toContain('\nkind: Issuer\n');
    expect(issuer).toContain('\n  name: ducks-in-a-row\n');
    expect(issuer).toContain(`      keyID: ${KID}\n`);
    expect(certificate).toContain('\nkind: Certificate\n');
    expect(certificate).toMatch(/issuerRef:\n {4}name: ducks-in-a-row\n {4}kind: Issuer\n/);
  });

  it('asks for the ECDSA key on the template curve', () => {
    const certificate = documents(certManager(resolveTemplateKey('ECDSA_P384', 384)))[1];
    expect(certificate).toContain('# This template requires ECDSA keys on curve P-384.');
    expect(certificate).toContain('  privateKey:\n    algorithm: ECDSA\n    size: 384\n');
  });

  it('rounds an RSA template minimum up to a size cert-manager accepts', () => {
    const certificate = documents(certManager(resolveTemplateKey('RSA', 3072)))[1];
    expect(certificate).toContain('# This template requires RSA keys of at least 3072 bits.');
    expect(certificate).toContain('  privateKey:\n    algorithm: RSA\n    size: 4096\n');
  });

  it('hedges to RSA 2048 when the template algorithm could not be read', () => {
    const certificate = documents(certManager())[1];
    expect(certificate).toContain('could not be read');
    expect(certificate).toContain('  privateKey:\n    algorithm: RSA\n    size: 2048\n');
  });

  it('says so instead of printing key settings for a key cert-manager cannot produce', () => {
    const certificate = documents(certManager(resolveTemplateKey('DSA', 1024)))[1];
    expect(certificate).toContain("cert-manager cannot produce this key; change the template's algorithm.");
    expect(certificate).not.toContain('privateKey:');
  });

  it('points an oversized RSA template at its key size, not its algorithm', () => {
    const certificate = documents(certManager(resolveTemplateKey('RSA', 16384)))[1];
    expect(certificate).toContain("lower the template's minimum key size");
    expect(certificate).not.toContain("change the template's algorithm");
    expect(certificate).not.toContain('privateKey:');
  });

  it('asks for the ECDSA key on the curve an ECDH template records, and names the setting to fix', () => {
    const certificate = documents(certManager(resolveTemplateKey('ECDH_P256', 256)))[1];
    expect(certificate).toContain('It records ECDH_P256');
    expect(certificate).toContain('  privateKey:\n    algorithm: ECDSA\n    size: 256\n');
  });

  it('carries the paste placeholder once the secret can no longer be shown', () => {
    const text = certManager(undefined, SECRET_PLACEHOLDER);
    expect(text).toContain(`--from-literal=secret='${SECRET_PLACEHOLDER}'`);
    expect(text).toContain(`    caBundle: ${CA_BUNDLE_PLACEHOLDER}\n`);
  });

  it('tells a ClusterIssuer user to change the Certificate issuerRef as well', () => {
    expect(certManager()).toContain("the Certificate's issuerRef kind to ClusterIssuer");
  });
});
