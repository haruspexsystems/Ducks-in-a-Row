import { describe, it, expect } from 'vitest';
import type { ServiceRightsReport, ServiceRightsRow } from '@/api/serviceRights';
import {
  hasEnrolmentEvidence,
  neededForText,
  needsAcknowledgement,
  rowsIn,
  rowsNotProven,
  statusLabel,
  statusPresentation,
} from './serviceRights';

/**
 * The rules behind the service rights check's acknowledgement (issue #440).
 * The backend decides every status; these decide what the operator is told
 * and when completing setup asks them to acknowledge it.
 */

function row(overrides: Partial<ServiceRightsRow>): ServiceRightsRow {
  return {
    id: 'ca-read',
    group: 'ca',
    title: 'The certificate view the inventory reads',
    status: 'proven',
    basis: 'exercised',
    neededFor: ['inventory'],
    detail: '',
    remedy: null,
    optional: false,
    template: null,
    ...overrides,
  };
}

function report(rows: ServiceRightsRow[]): ServiceRightsReport {
  return {
    caConnectionString: 'ca\\CA',
    identity: {
      processIdentity: 'NT AUTHORITY\\SYSTEM',
      isMachineIdentity: true,
      accountName: 'CORP\\DUCKS01$',
      accountSid: 'S-1-5-21-1-2-3-1105',
      domainName: 'CORP',
      groupCount: 1,
    },
    rows,
    simulated: false,
    checkedAt: '2026-09-26T09:00:00Z',
  };
}

const enrolment = (status: ServiceRightsRow['status']) =>
  row({ id: 'https-enrolment', group: 'endToEnd', status, basis: 'priorEnrollment' });

describe('needsAcknowledgement', () => {
  it('asks when nothing is enrolled and a row is unproven', () => {
    expect(needsAcknowledgement(report([enrolment('unproven'), row({ status: 'proven' })]))).toBe(true);
  });

  it('asks when nothing is enrolled and a row failed', () => {
    expect(needsAcknowledgement(report([row({ status: 'failed' })]))).toBe(true);
  });

  it('does not ask once an enrolment proves the rights', () => {
    expect(
      needsAcknowledgement(report([enrolment('proven'), row({ id: 'challenge-egress', status: 'unproven' })])),
    ).toBe(false);
  });

  it('does not ask when every row is proven or merely read', () => {
    expect(needsAcknowledgement(report([row({ status: 'proven' }), row({ id: 'x', status: 'inferred' })]))).toBe(false);
  });

  it('asks when the check could not be loaded at all', () => {
    expect(needsAcknowledgement(null)).toBe(true);
  });
});

describe('rowsNotProven', () => {
  it('names every row that is not proven, inferred ones included', () => {
    const rows = [
      row({ id: 'a', status: 'proven' }),
      row({ id: 'b', status: 'inferred' }),
      row({ id: 'c', status: 'unproven' }),
      row({ id: 'd', status: 'failed' }),
      row({ id: 'e', status: 'skipped' }),
    ];

    expect(rowsNotProven(report(rows)).map((r) => r.id)).toEqual(['b', 'c', 'd', 'e']);
  });
});

describe('hasEnrolmentEvidence', () => {
  it('is only the enrolment row being proven', () => {
    expect(hasEnrolmentEvidence(report([enrolment('proven')]))).toBe(true);
    expect(hasEnrolmentEvidence(report([enrolment('unproven')]))).toBe(false);
    expect(hasEnrolmentEvidence(report([row({ status: 'proven' })]))).toBe(false);
  });
});

describe('presentation', () => {
  it('never gives inferred the pass tone', () => {
    expect(statusPresentation('inferred').tone).not.toBe('pass');
    expect(statusPresentation('proven').tone).toBe('pass');
  });

  it('softens a failed optional row', () => {
    expect(statusLabel(row({ status: 'failed', optional: true }))).toBe('Not granted (optional)');
    expect(statusLabel(row({ status: 'failed', optional: false }))).toBe('Failed');
  });

  it('says what a right is needed for in plain words', () => {
    expect(neededForText(['issuance'])).toBe('Needed for issuance');
    expect(neededForText(['issuance', 'crlWatching'])).toBe('Needed for issuance and CRL watching');
    expect(neededForText(['issuance', 'inventory', 'revocation'])).toBe(
      'Needed for issuance, the certificate inventory and revocation',
    );
  });
});

describe('rowsIn', () => {
  it('keeps the report order and filters by group', () => {
    const rows = [row({ id: 'h', group: 'host' }), row({ id: 'c', group: 'ca' }), row({ id: 't', group: 'template' })];

    expect(rowsIn(report(rows), ['host', 'ca']).map((r) => r.id)).toEqual(['h', 'c']);
    expect(rowsIn(report(rows)).map((r) => r.id)).toEqual(['h', 'c', 't']);
  });
});
