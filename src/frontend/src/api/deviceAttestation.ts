import { ApiError, CSRF_HEADERS, fetchJson } from './client';

/**
 * API module for the device attestation admin surface on the ACME tab
 * (device-attest-01). A profile turns the feature on for one template; its
 * allowlist names the devices admitted in allowlist mode; the trust anchors
 * are the roots attestation chains verify against, built in roots plus any
 * custom ones. Every write hot applies to the ACME surface on the next
 * request.
 */

export type DeviceGateMode = 'allowlist' | 'open';
export type CsrIdentifierBinding = 'cn-or-san' | 'san-required' | 'none';

/**
 * Shared mutation helper: sends the CSRF header and reads the server's
 * { error } body on a refusal so the ApiError carries the real reason. A 204
 * No Content (delete) resolves to undefined rather than trying to parse a body.
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
  if (response.status === 204) return undefined as T;
  return (await response.json()) as T;
}

/** One device attestation profile row. */
export interface DeviceProfile {
  id: number;
  templateId: string;
  enabled: boolean;
  gateMode: DeviceGateMode;
  csrIdentifierBinding: CsrIdentifierBinding;
  allowlistCount: number;
  createdAt: string;
  updatedAt?: string | null;
}

/** Fetch every device attestation profile, newest first (admin only). */
export async function fetchDeviceProfiles(): Promise<DeviceProfile[]> {
  const body = await fetchJson<{ profiles: DeviceProfile[] }>(
    '/api/acme/device-attestation/profiles');
  return body.profiles;
}

/** Create a profile, turning device-attest-01 on for the template. */
export async function createDeviceProfile(input: {
  templateId: string;
  gateMode: DeviceGateMode;
  csrIdentifierBinding: CsrIdentifierBinding;
  enabled: boolean;
}): Promise<DeviceProfile> {
  return sendJson('/api/acme/device-attestation/profiles', 'POST', input);
}

/** Replace a profile's gate mode, CSR binding, and enabled flag. */
export async function updateDeviceProfile(
  id: number,
  input: { gateMode: DeviceGateMode; csrIdentifierBinding: CsrIdentifierBinding; enabled: boolean },
): Promise<DeviceProfile> {
  return sendJson(`/api/acme/device-attestation/profiles/${id}`, 'PUT', input);
}

/** Delete a profile, turning the feature off for its template (cascades the allowlist). */
export async function deleteDeviceProfile(id: number): Promise<void> {
  return sendJson(`/api/acme/device-attestation/profiles/${id}`, 'DELETE');
}

/** One allowlisted device. */
export interface DeviceAllowlistEntry {
  id: number;
  profileId: number;
  identifierValue: string;
  note?: string | null;
  createdAt: string;
}

/** Fetch a profile's allowlist (admin only). */
export async function fetchAllowlist(profileId: number): Promise<DeviceAllowlistEntry[]> {
  const body = await fetchJson<{ entries: DeviceAllowlistEntry[] }>(
    `/api/acme/device-attestation/profiles/${profileId}/allowlist`);
  return body.entries;
}

/** Admit a device (serial or UDID, raw permanent-identifier grammar form). */
export async function addAllowlistEntry(
  profileId: number,
  identifierValue: string,
  note: string | undefined,
): Promise<DeviceAllowlistEntry> {
  return sendJson(
    `/api/acme/device-attestation/profiles/${profileId}/allowlist`, 'POST',
    { identifierValue, note: note ?? null });
}

/** Replace an allowlist entry's identifier value and note. */
export async function updateAllowlistEntry(
  entryId: number,
  identifierValue: string,
  note: string | undefined,
): Promise<DeviceAllowlistEntry> {
  return sendJson(
    `/api/acme/device-attestation/allowlist/${entryId}`, 'PUT',
    { identifierValue, note: note ?? null });
}

/** Remove a device from an allowlist. */
export async function deleteAllowlistEntry(entryId: number): Promise<void> {
  return sendJson(`/api/acme/device-attestation/allowlist/${entryId}`, 'DELETE');
}

/**
 * One trust anchor. A built in root has a null id and cannot be deleted; the
 * fingerprint is the SHA-256 of the certificate's DER bytes, lowercase hex.
 */
export interface TrustAnchor {
  id: number | null;
  format: string;
  name: string;
  sha256Fingerprint: string;
  enabled: boolean;
  builtIn: boolean;
  createdAt?: string | null;
}

/** Fetch the trust anchors, built in roots first (admin only). */
export async function fetchTrustAnchors(): Promise<TrustAnchor[]> {
  const body = await fetchJson<{ anchors: TrustAnchor[] }>(
    '/api/acme/device-attestation/trust-anchors');
  return body.anchors;
}

/** Add a custom trust anchor from a pasted PEM certificate. */
export async function addTrustAnchor(input: {
  format: string;
  name: string;
  certificatePem: string;
}): Promise<TrustAnchor> {
  return sendJson('/api/acme/device-attestation/trust-anchors', 'POST', input);
}

/** Remove a custom trust anchor (built in roots cannot be removed). */
export async function deleteTrustAnchor(id: number): Promise<void> {
  return sendJson(`/api/acme/device-attestation/trust-anchors/${id}`, 'DELETE');
}
