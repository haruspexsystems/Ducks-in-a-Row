import { fetchJson } from './client';

/**
 * The service rights check (issue #440): what this server's own account may
 * do on the CA and on each template, and how sure the check can be of each
 * answer. The five statuses are the issue's; an "inferred" row is never a pass.
 */
export type RightsStatus = 'proven' | 'inferred' | 'unproven' | 'failed' | 'skipped';

/** What a row's status rests on. */
export type RightsBasis =
  | 'exercised'
  | 'reportedByCa'
  | 'readFromAcl'
  | 'priorEnrollment'
  | 'local'
  | 'notChecked';

/** Where a row belongs: this server, the CA, a template, or a path end to end. */
export type RightsGroup = 'host' | 'ca' | 'template' | 'endToEnd';

/** What a right is needed for. */
export type RightNeededFor = 'issuance' | 'inventory' | 'revocation' | 'crlWatching';

export interface ServiceRightsRow {
  /** domain, components, ca-connect, ca-enroll, ca-read, ca-officer, template:<name>, https-enrolment, challenge-egress */
  id: string;
  group: RightsGroup;
  title: string;
  status: RightsStatus;
  basis: RightsBasis;
  neededFor: RightNeededFor[];
  detail: string;
  remedy: string | null;
  /** True for a right only an optional feature needs (Issue and Manage, for revocation). */
  optional: boolean;
  template: string | null;
}

export interface ServiceRightsIdentity {
  processIdentity: string;
  isMachineIdentity: boolean;
  accountName: string | null;
  accountSid: string | null;
  domainName: string | null;
  groupCount: number;
}

export interface ServiceRightsReport {
  caConnectionString: string;
  identity: ServiceRightsIdentity;
  rows: ServiceRightsRow[];
  /** True on the dev host: the report describes an example estate, not a real CA. */
  simulated: boolean;
  checkedAt: string;
}

/**
 * The wizard's check against a candidate CA. No templates checks the CA
 * alone, which is what the Connection step asks for before templates exist.
 */
export async function checkSetupServiceRights(
  caConnectionString: string,
  templates: string[],
): Promise<ServiceRightsReport> {
  return fetchJson('/api/setup/service-rights', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ caConnectionString, templates }),
  });
}

/** The Settings page's check of the configured CA, served from the kept report while it is fresh. */
export async function fetchServiceRights(): Promise<ServiceRightsReport> {
  return fetchJson('/api/settings/service-rights');
}

/** The Settings page's "Check again": always a fresh check. */
export async function recheckServiceRights(): Promise<ServiceRightsReport> {
  return fetchJson('/api/settings/service-rights/check', { method: 'POST' });
}
