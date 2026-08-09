import { ApiError, CSRF_HEADERS, fetchJson } from './client';
import type { InvalidDomainEntry } from './settings';
import type { PagedResult } from '@/types';

/**
 * API module for the ACME tab (issue #129): EAB enforcement mode, EAB
 * credentials, and the ACME account inventory. The MAC secret appears only
 * in the create and regenerate responses; no other call ever returns one.
 */

export type EabEnforcementMode = 'off' | 'optional' | 'required';

/**
 * Shared mutation helper: sends the CSRF header, and unlike fetchJson reads
 * the server's { error } body on a refusal so the ApiError message carries
 * the real reason instead of the bare status text. Every mutating call in
 * this module goes through here, so the error envelope is parsed in exactly
 * one place.
 */
async function sendJson<T>(
  url: string,
  method: 'POST' | 'PUT' | 'DELETE',
  payload?: unknown,
): Promise<T> {
  const response = await fetch(url, {
    method,
    headers:
      payload !== undefined
        ? { 'Content-Type': 'application/json', ...CSRF_HEADERS }
        : CSRF_HEADERS,
    body: payload !== undefined ? JSON.stringify(payload) : undefined,
  });
  if (!response.ok) {
    const body = (await response.json().catch(() => null)) as { error?: string } | null;
    throw new ApiError(response.status, body?.error ?? response.statusText, url);
  }
  return (await response.json()) as T;
}

/** The enforcement mode in force plus how many valid accounts have no binding. */
export interface EabEnforcementSettings {
  mode: EabEnforcementMode;
  /** Valid accounts without a binding: grandfathered under Required. */
  unboundAccounts: number;
}

/** Fetch the EAB enforcement mode (admin only). */
export async function fetchEabEnforcement(): Promise<EabEnforcementSettings> {
  return fetchJson('/api/acme/eab/enforcement');
}

/** Successful enforcement update response. */
export interface EabEnforcementUpdateResult {
  mode: EabEnforcementMode;
  message: string;
}

/**
 * Change the enforcement mode. Applies to the next ACME request immediately;
 * there is no restart leg.
 */
export async function updateEabEnforcement(
  mode: EabEnforcementMode,
): Promise<EabEnforcementUpdateResult> {
  return sendJson('/api/acme/eab/enforcement', 'PUT', { mode });
}

/**
 * The AD owner linked to a credential, display and audit only. The name and
 * type are what the directory answered when the link was made.
 */
export interface EabCredentialPrincipal {
  sid: string;
  /** The account name, e.g. "jsmith" or "WEB01$". */
  name: string;
  /** "user", "computer", "group", or "service account". */
  type: string;
}

/** One credential row of the dashboard list. Never carries a secret. */
export interface EabCredentialSummary {
  id: number;
  keyId: string;
  name: string;
  status: 'active' | 'revoked';
  expiresAt?: string | null;
  /**
   * The credential's domain namespace (normalized). Its accounts may only
   * order inside these domains, across every template; empty means no extra
   * restriction.
   */
  namespaces: string[];
  /** The linked AD owner, or null when the credential has none. */
  adPrincipal?: EabCredentialPrincipal | null;
  createdAt: string;
  updatedAt?: string | null;
  revokedAt?: string | null;
  secretRegeneratedAt?: string | null;
  boundAccountCount: number;
  /** "revoked", "expired", or "active", in that precedence (server computed). */
  effectiveStatus: 'active' | 'revoked' | 'expired';
}

/** Fetch every EAB credential, newest first (admin only). */
export async function fetchEabCredentials(): Promise<EabCredentialSummary[]> {
  const body = await fetchJson<{ credentials: EabCredentialSummary[] }>(
    '/api/acme/credentials');
  return body.credentials;
}

/**
 * The create and regenerate response: the only two places the plaintext
 * secret ever appears. The dashboard shows it once and the API never returns
 * it again.
 */
export interface EabCredentialWithSecret {
  id: number;
  keyId: string;
  name: string;
  status: string;
  expiresAt?: string | null;
  createdAt: string;
  secretRegeneratedAt?: string | null;
  secret: string;
}

/**
 * A credential save either lands, or is refused with per entry reasons for
 * the namespace domains (the same shape as the settings allowed domain
 * list). Any other refusal still throws ApiError.
 */
export type EabCredentialSaveOutcome<T> =
  | { kind: 'saved'; result: T }
  | { kind: 'invalid'; error: string; invalidEntries: InvalidDomainEntry[] };

/**
 * Like sendJson, but a 400 becomes an outcome instead of a throw, because
 * the body may carry per entry namespace reasons the card renders next to
 * the editor. Create and update go through here.
 */
async function sendJsonWithEntryReasons<T>(
  url: string,
  method: 'POST' | 'PUT',
  payload: unknown,
): Promise<EabCredentialSaveOutcome<T>> {
  const response = await fetch(url, {
    method,
    headers: { 'Content-Type': 'application/json', ...CSRF_HEADERS },
    body: JSON.stringify(payload),
  });
  if (response.status === 400) {
    const body = (await response.json().catch(() => null)) as
      | { error?: string; invalidEntries?: InvalidDomainEntry[] }
      | null;
    return {
      kind: 'invalid',
      error: body?.error ?? 'The request was not accepted.',
      invalidEntries: body?.invalidEntries ?? [],
    };
  }
  if (!response.ok) {
    const body = (await response.json().catch(() => null)) as { error?: string } | null;
    throw new ApiError(response.status, body?.error ?? response.statusText, url);
  }
  return { kind: 'saved', result: (await response.json()) as T };
}

/**
 * Create a credential. expiresAt, when given, is a UTC ISO timestamp;
 * domains become the credential's namespace (empty for no restriction).
 */
export async function createEabCredential(
  name: string,
  expiresAt: string | undefined,
  domains: string[],
): Promise<EabCredentialSaveOutcome<EabCredentialWithSecret>> {
  return sendJsonWithEntryReasons('/api/acme/credentials', 'POST',
    { name, expiresAt: expiresAt ?? null, domains });
}

/** Successful credential update response. */
export interface EabCredentialUpdateResult {
  id: number;
  keyId: string;
  name: string;
  status: string;
  expiresAt?: string | null;
  namespaces: string[];
  updatedAt?: string | null;
  message: string;
}

/**
 * Replace a credential's name, expiry, and namespace. The key id and secret
 * stay; the change applies to the next ACME request immediately. A null
 * expiresAt clears the expiry, which (like a future one) puts an expired
 * credential back in use.
 */
export async function updateEabCredential(
  id: number,
  name: string,
  expiresAt: string | null,
  domains: string[],
): Promise<EabCredentialSaveOutcome<EabCredentialUpdateResult>> {
  return sendJsonWithEntryReasons(`/api/acme/credentials/${id}`, 'PUT',
    { name, expiresAt, domains });
}

/**
 * Rotate the secret on the same key id. Every handed out copy of the old
 * secret stops verifying the moment this returns.
 */
export async function regenerateEabSecret(id: number): Promise<EabCredentialWithSecret> {
  return sendJson(`/api/acme/credentials/${id}/regenerate`, 'POST');
}

/** Revocation response. */
export interface EabRevokeResult {
  id: number;
  keyId: string;
  status: string;
  revokedAt?: string | null;
}

/**
 * Revoke a credential. Terminal: new registrations with it are rejected and
 * new orders from its bound accounts are suspended.
 */
export async function revokeEabCredential(id: number): Promise<EabRevokeResult> {
  return sendJson(`/api/acme/credentials/${id}/revoke`, 'POST');
}

/** An account bound to a credential, for the row expander. */
export interface EabBoundAccount {
  id: number;
  accountId: string;
  status: string;
  contacts?: string[] | null;
  createdAt: string;
}

/** Fetch the accounts bound to one credential (admin only). */
export async function fetchEabBoundAccounts(id: number): Promise<EabBoundAccount[]> {
  const body = await fetchJson<{ accounts: EabBoundAccount[] }>(
    `/api/acme/credentials/${id}/accounts`);
  return body.accounts;
}

/** A directory principal offered by the owner picker. */
export interface AdPrincipal extends EabCredentialPrincipal {
  /** The full DN, for disambiguation; null when the directory omits it. */
  distinguishedName?: string | null;
}

/**
 * Search the directory for the owner picker (admin only). Best effort: a
 * server that is not domain joined or cannot reach the directory answers
 * with an empty list, the same as no match. The signal lets the picker
 * abort a superseded keystroke's request, which also cancels the LDAP
 * search server side.
 */
export async function searchDirectoryPrincipals(
  query: string,
  signal?: AbortSignal,
): Promise<AdPrincipal[]> {
  const params = new URLSearchParams({ query });
  const body = await fetchJson<{ principals: AdPrincipal[] }>(
    `/api/acme/directory-principals?${params}`, { signal });
  return body.principals;
}

/** Successful owner link change response. */
export interface EabPrincipalUpdateResult {
  id: number;
  keyId: string;
  adPrincipal: EabCredentialPrincipal | null;
  updatedAt?: string | null;
}

/**
 * Link an AD principal as the credential's owner (display and audit only).
 * Only the SID travels; the server re-resolves it and stores the directory's
 * answer, so an unresolvable SID is refused with a 400.
 */
export async function setEabCredentialPrincipal(
  id: number,
  sid: string,
): Promise<EabPrincipalUpdateResult> {
  return sendJson(`/api/acme/credentials/${id}/principal`, 'PUT', { sid });
}

/** Remove the credential's owner link. Idempotent when none is set. */
export async function clearEabCredentialPrincipal(
  id: number,
): Promise<EabPrincipalUpdateResult> {
  return sendJson(`/api/acme/credentials/${id}/principal`, 'DELETE');
}

/** The bound credential of an account row, or null for an unbound account. */
export interface AcmeAccountCredentialRef {
  id: number;
  keyId: string;
  name: string;
  status: string;
}

/** One account row of the inventory list. */
export interface AcmeAccountRow {
  id: number;
  accountId: string;
  status: string;
  contacts?: string[] | null;
  createdAt: string;
  ordersCount: number;
  lastOrderAt?: string | null;
  credential?: AcmeAccountCredentialRef | null;
}

/**
 * Whether an account carries an EAB binding. An axis of its own: it combines
 * with the status filter rather than replacing it, which is what makes "valid
 * and still unbound", the grandfathered set, a single question.
 */
export type AcmeAccountBindingFilter = 'all' | 'bound' | 'unbound' | 'boundToRevoked';

/**
 * Account status. Only valid and deactivated exist, because those are the
 * only two values anything ever writes; RFC 8555 also defines revoked but
 * nothing in the product produces it.
 */
export type AcmeAccountStatusFilter = 'all' | 'valid' | 'deactivated';

/**
 * Order activity, as a rolling window resolved on the server so the boundary
 * uses the server clock and a bookmarked link keeps its meaning. The idle
 * windows include accounts that never ordered; 'never' isolates only those.
 */
export type AcmeAccountActivityFilter =
  | 'any'
  | 'never'
  | 'idle30'
  | 'idle90'
  | 'idle180'
  | 'active7'
  | 'active30';

/** Query parameters for the account inventory. */
export interface AcmeAccountsQuery {
  search?: string;
  binding?: AcmeAccountBindingFilter;
  status?: AcmeAccountStatusFilter;
  credentialId?: number;
  activity?: AcmeAccountActivityFilter;
  /**
   * Absolute date bounds, as UTC instants. The caller resolves its own
   * timezone before sending: the After bounds are inclusive and the Before
   * bounds are exclusive, so filtering on a whole local day means sending the
   * start of that day and the start of the next one.
   */
  registeredAfter?: string;
  registeredBefore?: string;
  lastOrderAfter?: string;
  lastOrderBefore?: string;
  sortBy?: string;
  sortDesc?: boolean;
  skip?: number;
  take?: number;
}

/** Search, filter, sort, and page the ACME account inventory (admin only). */
export async function fetchAcmeAccounts(
  query: AcmeAccountsQuery = {},
): Promise<PagedResult<AcmeAccountRow>> {
  const params = new URLSearchParams();
  if (query.search) params.set('search', query.search);
  // The three enum filters omit their "no filter" value rather than sending
  // it, so a default view has a clean URL.
  if (query.binding && query.binding !== 'all') params.set('binding', query.binding);
  if (query.status && query.status !== 'all') params.set('status', query.status);
  if (query.credentialId !== undefined) params.set('credentialId', String(query.credentialId));
  if (query.activity && query.activity !== 'any') params.set('activity', query.activity);
  if (query.registeredAfter) params.set('registeredAfter', query.registeredAfter);
  if (query.registeredBefore) params.set('registeredBefore', query.registeredBefore);
  if (query.lastOrderAfter) params.set('lastOrderAfter', query.lastOrderAfter);
  if (query.lastOrderBefore) params.set('lastOrderBefore', query.lastOrderBefore);
  if (query.sortBy) params.set('sortBy', query.sortBy);
  if (query.sortDesc) params.set('sortDesc', 'true');
  if (query.skip !== undefined) params.set('skip', String(query.skip));
  if (query.take !== undefined) params.set('take', String(query.take));
  const str = params.toString();
  return fetchJson(`/api/acme/accounts${str ? `?${str}` : ''}`);
}

/** Deactivation response. */
export interface AcmeAccountDeactivateResult {
  id: number;
  accountId: string;
  status: string;
  /** Open (pending, ready, processing) orders invalidated with the account. */
  invalidatedOrders: number;
}

/**
 * Deactivate an account. Terminal (RFC 8555 section 7.3.6): every later ACME
 * request it signs is rejected, and its open orders are invalidated.
 */
export async function deactivateAcmeAccount(
  id: number,
): Promise<AcmeAccountDeactivateResult> {
  return sendJson(`/api/acme/accounts/${id}/deactivate`, 'POST');
}
