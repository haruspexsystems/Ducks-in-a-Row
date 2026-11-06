import { fetchJson } from './client';
import type { PagedResult } from '@/types';

/**
 * The administrator audit trail (issue #634). Read only by design: the server
 * writes a row for every administrator action and the retention job is the
 * only thing that removes one, so nothing here can edit or silence the trail.
 */
export interface AuditEntry {
  id: number;
  /** When the action happened, UTC. */
  occurredAt: string;
  /** The Windows identity that acted, or "(anonymous)" on a dev host with auth off. */
  actor: string;
  /** A stable dotted name, such as "settings.allowed-domains.changed". */
  action: string;
  target?: string | null;
  before?: string | null;
  after?: string | null;
}

export interface AuditEntriesQuery {
  actor?: string;
  skip?: number;
  take?: number;
}

/** One page of the trail, newest first. */
export async function fetchAuditEntries(query: AuditEntriesQuery = {}): Promise<PagedResult<AuditEntry>> {
  const params = new URLSearchParams();
  if (query.actor) params.set('actor', query.actor);
  if (query.skip) params.set('skip', String(query.skip));
  if (query.take) params.set('take', String(query.take));
  const suffix = params.toString();
  return fetchJson(`/api/audit/entries${suffix ? `?${suffix}` : ''}`);
}

/** Every identity with a row, for the actor filter. */
export async function fetchAuditActors(): Promise<string[]> {
  const body = await fetchJson<{ actors: string[] }>('/api/audit/actors');
  return body.actors;
}

/** Refused requests from one source address over the window. */
export interface SignInFailureSource {
  sourceAddress: string;
  count: number;
  /** Credentials offered and refused. */
  unauthorized: number;
  /** Signed in, but not an administrator. */
  forbidden: number;
  firstAt: string;
  lastAt: string;
}

export interface SignInFailures {
  days: number;
  since: string;
  total: number;
  sources: SignInFailureSource[];
}

/** Refused dashboard sign ins over the last N days, most recent source first. */
export async function fetchSignInFailures(days = 30): Promise<SignInFailures> {
  return fetchJson(`/api/audit/sign-in-failures?days=${days}`);
}
