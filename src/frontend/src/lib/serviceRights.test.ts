import { describe, it, expect } from 'vitest';
import type { ServiceRightsReport, ServiceRightsRow } from '@/api/serviceRights';
import {
  hasEnrolmentEvidence,
  isNotNeeded,
  neededForText,
  needsAcknowledgement,
  rowPresentation,
  rowsIn,
  rowsNotProven,
  statusLabel,
  statusPresentation,
  templatesNotCheckedText,
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
    templatesNotChecked: 0,
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

describe('rows monitor mode never uses (issue #470)', () => {
  const template = row({
    id: 'template:WebServer',
    group: 'template',
    status: 'failed',
    neededFor: ['issuance'],
    remedy: 'Grant Enroll',
    notNeeded: 'monitorMode',
  });

  it('reads as not needed, never as a failure', () => {
    expect(isNotNeeded(template)).toBe(true);
    expect(statusLabel(template)).toBe('Not needed in monitor mode');
    expect(rowPresentation(template).tone).not.toBe('fail');
  });

  it('is left out of the acknowledgement', () => {
    const r = report([template, row({ id: 'ca-read', status: 'proven' })]);

    expect(rowsNotProven(r)).toEqual([]);
    expect(needsAcknowledgement(r)).toBe(false);
  });

  it('leaves a needed row exactly as it was', () => {
    const needed = row({ id: 'ca-read', status: 'failed', notNeeded: null });

    expect(isNotNeeded(needed)).toBe(false);
    expect(statusLabel(needed)).toBe('Failed');
    expect(needsAcknowledgement(report([needed]))).toBe(true);
  });
});

describe('templates the Settings check left out (issue #478)', () => {
  const withNotChecked = (templatesNotChecked: number) => ({ ...report([]), templatesNotChecked });

  it('says nothing when every enabled template was checked', () => {
    expect(templatesNotCheckedText(withNotChecked(0))).toBeNull();
  });

  it('says how many were left out, and that the rows above say nothing of them', () => {
    expect(templatesNotCheckedText(withNotChecked(4))).toBe(
      '4 more templates enabled for ACME were not checked, because one check reads a limited number of templates. Nothing above says whether this server holds Enroll on them.',
    );
  });

  it('reads as one template when one was left out', () => {
    expect(templatesNotCheckedText(withNotChecked(1))).toBe(
      '1 more template enabled for ACME was not checked, because one check reads a limited number of templates. Nothing above says whether this server holds Enroll on it.',
    );
  });

  it('says the left out templates need no Enroll in monitor mode', () => {
    // A server switched from full to monitor mode keeps its enabled templates, and the
    // rows above already read as not needed, so the line must not ask a question.
    const monitor = {
      ...report([row({ id: 'template-enroll', group: 'template', status: 'unproven', notNeeded: 'monitorMode' })]),
      templatesNotChecked: 4,
    };
    expect(templatesNotCheckedText(monitor)).toBe(
      '4 more templates enabled for ACME were not checked, because one check reads a limited number of templates. Monitor mode needs no Enroll on them, so this matters only after a switch to full mode.',
    );
  });

  it('shows nothing for a payload that does not carry the count', () => {
    const older: Partial<ServiceRightsReport> = { ...report([]) };
    delete older.templatesNotChecked;
    expect(templatesNotCheckedText(older as ServiceRightsReport)).toBeNull();
  });
});
