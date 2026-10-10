import { describe, it, expect } from 'vitest';
import { certManagerPrivateKey, resolveTemplateKey } from './templateKey';

/**
 * cert-manager's privateKey settings for a template (issue #439). cert-manager
 * accepts RSA at 2048, 4096 and 8192 bits only and defaults to RSA 2048, so the
 * cases worth pinning are the rounding between those sizes and the curves.
 */
describe('certManagerPrivateKey', () => {
  it('answers RSA 2048 for the stock RSA template', () => {
    expect(certManagerPrivateKey(resolveTemplateKey('RSA', 2048))).toEqual({
      algorithm: 'RSA',
      size: 2048,
    });
  });

  it('rounds an RSA minimum between two accepted sizes up to the next one', () => {
    expect(certManagerPrivateKey(resolveTemplateKey('RSA', 3072))).toEqual({
      algorithm: 'RSA',
      size: 4096,
    });
    expect(certManagerPrivateKey(resolveTemplateKey('RSA', 4097))).toEqual({
      algorithm: 'RSA',
      size: 8192,
    });
  });

  it('keeps an RSA minimum that is already an accepted size', () => {
    expect(certManagerPrivateKey(resolveTemplateKey('RSA', 4096))?.size).toBe(4096);
    expect(certManagerPrivateKey(resolveTemplateKey('RSA', 8192))?.size).toBe(8192);
  });

  it('refuses an RSA minimum above the largest size cert-manager accepts', () => {
    expect(certManagerPrivateKey(resolveTemplateKey('RSA', 16384))).toBeNull();
  });

  it('never goes below the RSA floor for a template recording less', () => {
    expect(certManagerPrivateKey(resolveTemplateKey('RSA', 1024))?.size).toBe(2048);
  });

  it('hedges to RSA 2048 when the template algorithm could not be read', () => {
    expect(certManagerPrivateKey(resolveTemplateKey(null, null))).toEqual({
      algorithm: 'RSA',
      size: 2048,
    });
  });

  it('names each NIST curve by its size, P-521 included', () => {
    expect(certManagerPrivateKey(resolveTemplateKey('ECDSA_P256', 256))).toEqual({
      algorithm: 'ECDSA',
      size: 256,
    });
    expect(certManagerPrivateKey(resolveTemplateKey('ECDSA_P384', 384))?.size).toBe(384);
    expect(certManagerPrivateKey(resolveTemplateKey('ECDSA_P521', 521))?.size).toBe(521);
  });

  it('answers the ECDSA key on the same curve for an ECDH template', () => {
    expect(certManagerPrivateKey(resolveTemplateKey('ECDH_P384', 384))).toEqual({
      algorithm: 'ECDSA',
      size: 384,
    });
  });

  it('refuses an algorithm no ACME client can produce', () => {
    expect(certManagerPrivateKey(resolveTemplateKey('DSA', 1024))).toBeNull();
  });
});
