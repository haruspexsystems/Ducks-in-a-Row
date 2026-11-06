import { describe, it, expect } from 'vitest';
import { CA_ACCESS_DENIED_PROBLEM, describeChainLoadFailure } from './caCertificates';

/**
 * What the CA certificates card says when the chain does not load (issue #476).
 * The server answers a CA refusal and a CA outage with the same 503, so the
 * problem type is what keeps the card from telling an administrator to wait out
 * a missing right.
 */
describe('describeChainLoadFailure', () => {
  const remedy =
    "CA certificate chain access denied: ... Grant the service account 'Request Certificates' on the CA ...";

  it('shows the remedy the server sent for a refusal, not the outage sentence', () => {
    const text = describeChainLoadFailure({
      status: 503,
      problemType: CA_ACCESS_DENIED_PROBLEM,
      problemDetail: remedy,
    });

    expect(text).toBe(remedy);
    expect(text).not.toMatch(/try again shortly/i);
  });

  it('still says something useful for a refusal that carried no detail', () => {
    const text = describeChainLoadFailure({ status: 503, problemType: CA_ACCESS_DENIED_PROBLEM });

    expect(text).toMatch(/refused/);
    expect(text).not.toMatch(/try again shortly/i);

    const empty = describeChainLoadFailure({
      status: 503, problemType: CA_ACCESS_DENIED_PROBLEM, problemDetail: '',
    });
    expect(empty).toMatch(/refused/);
  });

  it('keeps the outage sentence for a 503 that is not a refusal', () => {
    expect(describeChainLoadFailure({ status: 503 })).toBe(
      'The certificate authority is unavailable. Try again shortly.');
  });

  it('points at the service log for anything else', () => {
    expect(describeChainLoadFailure({ status: 500 })).toMatch(/service log/);
    expect(describeChainLoadFailure(undefined)).toMatch(/service log/);
  });

  it('matches the problem type the server emits', () => {
    // DashboardProblemType.CaAccessDenied on the server. A slug is a contract
    // with every release that emits it, so a rename on either side fails here.
    expect(CA_ACCESS_DENIED_PROBLEM).toBe('https://ducksinarow.dev/problems/ca-access-denied');
  });
});
