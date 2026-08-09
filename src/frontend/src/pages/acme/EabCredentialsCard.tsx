import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  KeyRound,
  Loader2,
  Pencil,
  Plus,
  Terminal,
  X,
} from 'lucide-react';
import {
  clearEabCredentialPrincipal,
  createEabCredential,
  fetchEabBoundAccounts,
  fetchEabCredentials,
  regenerateEabSecret,
  revokeEabCredential,
  setEabCredentialPrincipal,
  updateEabCredential,
  type EabCredentialPrincipal,
  type EabCredentialSummary,
  type EabCredentialWithSecret,
} from '@/api/acme';
import type { InvalidDomainEntry } from '@/api/settings';
import { CopyButton } from '@/components/CopyButton';
import { DomainListEditor } from '@/components/DomainListEditor';
import { formatDate, formatDateTime } from '@/types';
import { EabClientSnippets } from './EabClientSnippets';
import { PrincipalPicker } from './PrincipalPicker';

const statusColors: Record<EabCredentialSummary['effectiveStatus'], string> = {
  active: 'bg-emerald-100 dark:bg-emerald-500/15 text-emerald-800 dark:text-emerald-300',
  revoked: 'bg-violet-100 dark:bg-violet-500/15 text-violet-800 dark:text-violet-300',
  expired: 'bg-red-100 dark:bg-red-500/15 text-red-800 dark:text-red-300',
};

/** A pending two step confirm on one row. */
type RowConfirm = { id: number; action: 'regenerate' | 'revoke' } | null;

/** The show once panel content: a freshly created or regenerated secret. */
type SecretPanel = { kind: 'created' | 'regenerated'; credential: EabCredentialWithSecret } | null;

/**
 * Dashboard card for EAB credentials: create, hand out (show once), rotate,
 * and revoke. The secret is visible exactly once, in the emerald panel after
 * create or regenerate; the server stores it encrypted and no API call
 * returns it again. Revocation is terminal and suspends new orders from
 * every account bound to the credential.
 */
export function EabCredentialsCard() {
  const queryClient = useQueryClient();

  const { data: credentials, isLoading, isError } = useQuery({
    queryKey: ['acme', 'eab-credentials'],
    queryFn: fetchEabCredentials,
    staleTime: 30_000,
    retry: false,
  });

  const [formOpen, setFormOpen] = useState(false);
  const [name, setName] = useState('');
  const [expiry, setExpiry] = useState('');
  const [domains, setDomains] = useState<string[]>([]);
  const [submitting, setSubmitting] = useState(false);
  const [formError, setFormError] = useState<string | null>(null);
  const [formInvalidEntries, setFormInvalidEntries] = useState<InvalidDomainEntry[]>([]);

  const [secretPanel, setSecretPanel] = useState<SecretPanel>(null);
  const [confirm, setConfirm] = useState<RowConfirm>(null);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [editId, setEditId] = useState<number | null>(null);
  const [setupId, setSetupId] = useState<number | null>(null);

  // exact: the per row bound accounts queries nest under this key, and
  // nothing this card does changes a bound account row, so invalidating
  // them here would only refetch identical data for every open expander.
  const refresh = () =>
    queryClient.invalidateQueries({ queryKey: ['acme', 'eab-credentials'], exact: true });

  const handleCreate = async () => {
    setSubmitting(true);
    setFormError(null);
    setFormInvalidEntries([]);
    try {
      // datetime-local is the admin's local wall clock; send the exact
      // instant as UTC ISO so the server compares apples to apples.
      const expiresAt = expiry ? new Date(expiry).toISOString() : undefined;
      const outcome = await createEabCredential(name.trim(), expiresAt, domains);
      if (outcome.kind === 'invalid') {
        setFormError(outcome.error);
        setFormInvalidEntries(outcome.invalidEntries);
        return;
      }
      setSecretPanel({ kind: 'created', credential: outcome.result });
      setFormOpen(false);
      setName('');
      setExpiry('');
      setDomains([]);
      await refresh();
    } catch (err) {
      setFormError(err instanceof Error ? err.message : 'Creating failed');
    } finally {
      setSubmitting(false);
    }
  };

  const handleRegenerate = async (id: number) => {
    setBusyId(id);
    setActionError(null);
    setConfirm(null);
    try {
      const regenerated = await regenerateEabSecret(id);
      setSecretPanel({ kind: 'regenerated', credential: regenerated });
      await refresh();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Regenerating failed');
    } finally {
      setBusyId(null);
    }
  };

  const handleRevoke = async (id: number) => {
    setBusyId(id);
    setActionError(null);
    setConfirm(null);
    try {
      await revokeEabCredential(id);
      // A show once panel for this credential now displays a secret that can
      // never verify; take it off the screen so it cannot be handed out.
      setSecretPanel((panel) => (panel?.credential.id === id ? null : panel));
      // The revoked row loses its Client setup and Edit toggles, so an open
      // panel of either kind would be stranded with no way to close it.
      setSetupId((open) => (open === id ? null : open));
      setEditId((open) => (open === id ? null : open));
      // The accounts card shows the credential status too; refetch both in
      // parallel, they are independent.
      await Promise.all([
        refresh(),
        queryClient.invalidateQueries({ queryKey: ['acme', 'accounts'] }),
      ]);
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Revoking failed');
    } finally {
      setBusyId(null);
    }
  };

  return (
    <div className="bg-surface border border-hairline rounded-lg p-6 space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <KeyRound className="h-4 w-4 text-certus-600" />
          <h3 className="text-sm font-semibold text-ink">EAB Credentials</h3>
        </div>
        <button
          onClick={() => {
            setFormOpen(!formOpen);
            setFormError(null);
          }}
          className="inline-flex items-center gap-2 px-3 py-1.5 text-sm font-medium
                     text-certus-700 dark:text-certus-300 bg-certus-50 dark:bg-certus-500/10 border border-certus-200 dark:border-certus-500/30 rounded-lg
                     hover:bg-certus-100 dark:bg-certus-500/15 transition-colors"
        >
          <Plus className="h-4 w-4" />
          New credential
        </button>
      </div>
      <p className="text-sm text-muted">
        A credential is a key id and MAC secret an ACME client presents when
        it registers. Credentials are multi-use: hand one to each team or
        system, and revoke it to cut that consumer off. The secret is shown
        exactly once, right after create or regenerate. A domain namespace,
        when set, limits the credential's accounts to those domains across
        every template; when the allowed domain list on the Settings page is
        on, that list stays the ceiling and a namespace narrows within it.
      </p>

      {formOpen && (
        <div className="border border-hairline rounded-lg p-4 space-y-3 bg-sunken">
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <div>
              <label className="block text-xs font-medium text-ink-mid mb-1">
                Name
              </label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. Web team, Kubernetes cluster"
                maxLength={200}
                className="w-full px-3 py-2 bg-surface border border-hairline-strong rounded-lg text-sm
                           placeholder:text-faint focus:outline-none focus:ring-2
                           focus:ring-certus-500 focus:border-certus-500"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-ink-mid mb-1">
                Expiry (optional)
              </label>
              <input
                type="datetime-local"
                value={expiry}
                onChange={(e) => setExpiry(e.target.value)}
                className="w-full px-3 py-2 bg-surface border border-hairline-strong rounded-lg text-sm
                           text-ink-soft focus:outline-none focus:ring-2
                           focus:ring-certus-500 focus:border-certus-500"
              />
            </div>
          </div>
          <div>
            <label className="block text-xs font-medium text-ink-mid mb-1">
              Domain namespace (optional)
            </label>
            <DomainListEditor
              domains={domains}
              onAdd={(domain) => {
                setFormError(null);
                setFormInvalidEntries([]);
                if (!domains.includes(domain)) setDomains([...domains, domain]);
              }}
              onRemove={(domain) => setDomains(domains.filter((d) => d !== domain))}
              emptyText="No namespace. Accounts using this credential may order for any domain the server allows."
            />
            <p className="text-xs text-faint mt-1">
              Accounts registered with this credential may only order
              certificates inside these domains, across every template. Each
              entry covers the domain and its subdomains.
            </p>
          </div>
          {formError && <EntryErrors error={formError} invalidEntries={formInvalidEntries} />}
          <div className="flex items-center justify-end gap-2">
            <button
              onClick={() => setFormOpen(false)}
              className="px-4 py-2 text-sm font-medium text-ink-mid hover:text-ink-strong"
            >
              Cancel
            </button>
            <button
              onClick={handleCreate}
              disabled={submitting || name.trim().length === 0}
              className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium text-white
                         bg-certus-600 rounded-lg hover:bg-certus-700 disabled:opacity-50
                         transition-colors"
            >
              {submitting ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Create'}
            </button>
          </div>
        </div>
      )}

      {secretPanel && (
        <div className="bg-emerald-50 dark:bg-emerald-500/10 border border-emerald-300 rounded-lg p-4 space-y-3">
          <div className="flex items-start justify-between gap-4">
            <div>
              <p className="text-sm font-semibold text-emerald-900 dark:text-emerald-200">
                {secretPanel.kind === 'created'
                  ? `Credential "${secretPanel.credential.name}" created`
                  : `New secret for "${secretPanel.credential.name}"`}
              </p>
              <p className="text-xs text-emerald-800 dark:text-emerald-300 mt-1">
                Copy the secret now. It is shown only this once; the server
                stores it encrypted and cannot show it again. If it is lost,
                regenerate it here.
                {secretPanel.kind === 'regenerated' &&
                  ' Every copy of the previous secret has stopped working.'}
              </p>
            </div>
            <button
              onClick={() => setSecretPanel(null)}
              className="text-emerald-700 dark:text-emerald-300 hover:text-emerald-900 dark:text-emerald-200"
              aria-label="Dismiss the secret panel"
              title="Dismiss. The secret cannot be shown again."
            >
              <X className="h-4 w-4" />
            </button>
          </div>
          <dl className="space-y-2">
            <div className="flex items-center gap-2">
              <dt className="text-xs font-medium text-emerald-900 dark:text-emerald-200 w-24 shrink-0">Key ID</dt>
              <dd className="text-xs font-mono text-emerald-900 dark:text-emerald-200 break-all">
                {secretPanel.credential.keyId}
              </dd>
              <CopyButton value={secretPanel.credential.keyId} label="key ID" />
            </div>
            <div className="flex items-center gap-2">
              <dt className="text-xs font-medium text-emerald-900 dark:text-emerald-200 w-24 shrink-0">HMAC secret</dt>
              <dd className="text-xs font-mono text-emerald-900 dark:text-emerald-200 break-all">
                {secretPanel.credential.secret}
              </dd>
              <CopyButton value={secretPanel.credential.secret} label="HMAC secret" />
            </div>
          </dl>
          <div className="border-t border-emerald-200 dark:border-emerald-500/30 pt-3">
            <EabClientSnippets
              keyId={secretPanel.credential.keyId}
              secret={secretPanel.credential.secret}
            />
          </div>
        </div>
      )}

      {actionError && (
        <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/30 rounded-lg p-3 flex items-start gap-2">
          <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5" />
          <p className="text-xs text-red-700 dark:text-red-300">{actionError}</p>
        </div>
      )}

      {isLoading ? (
        <div className="flex items-center gap-2 text-sm text-faint py-2">
          <Loader2 className="h-4 w-4 animate-spin" />
          Loading credentials…
        </div>
      ) : isError ? (
        <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/30 rounded-lg p-3 flex items-start gap-2">
          <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5" />
          <p className="text-xs text-red-700 dark:text-red-300">The credentials could not be loaded.</p>
        </div>
      ) : (credentials ?? []).length === 0 ? (
        <p className="text-sm text-faint py-2">
          No credentials yet. Create one and hand its key id and secret to an
          ACME client.
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs text-muted uppercase border-b border-hairline">
                <th className="py-2 pr-3 font-medium" />
                <th className="py-2 pr-3 font-medium">Name</th>
                <th className="py-2 pr-3 font-medium">Key ID</th>
                <th className="py-2 pr-3 font-medium">Status</th>
                <th className="py-2 pr-3 font-medium">Namespace</th>
                <th className="py-2 pr-3 font-medium">Accounts</th>
                <th className="py-2 pr-3 font-medium">Expires</th>
                <th className="py-2 pr-3 font-medium">Created</th>
                <th className="py-2 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {(credentials ?? []).map((credential) => (
                <CredentialRow
                  key={credential.id}
                  credential={credential}
                  expanded={expandedId === credential.id}
                  onToggleExpand={() =>
                    setExpandedId(expandedId === credential.id ? null : credential.id)
                  }
                  confirm={confirm?.id === credential.id ? confirm.action : null}
                  onConfirmChange={(action) =>
                    setConfirm(action ? { id: credential.id, action } : null)
                  }
                  busy={busyId === credential.id}
                  onRegenerate={() => handleRegenerate(credential.id)}
                  onRevoke={() => handleRevoke(credential.id)}
                  editing={editId === credential.id}
                  onEditChange={(on) => setEditId(on ? credential.id : null)}
                  onEditSaved={async () => {
                    setEditId(null);
                    await refresh();
                  }}
                  showingSetup={setupId === credential.id}
                  onSetupChange={(on) => setSetupId(on ? credential.id : null)}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}

function CredentialRow({
  credential,
  expanded,
  onToggleExpand,
  confirm,
  onConfirmChange,
  busy,
  onRegenerate,
  onRevoke,
  editing,
  onEditChange,
  onEditSaved,
  showingSetup,
  onSetupChange,
}: {
  credential: EabCredentialSummary;
  expanded: boolean;
  onToggleExpand: () => void;
  confirm: 'regenerate' | 'revoke' | null;
  onConfirmChange: (action: 'regenerate' | 'revoke' | null) => void;
  busy: boolean;
  onRegenerate: () => void;
  onRevoke: () => void;
  editing: boolean;
  onEditChange: (on: boolean) => void;
  onEditSaved: () => Promise<void>;
  showingSetup: boolean;
  onSetupChange: (on: boolean) => void;
}) {
  const revoked = credential.status === 'revoked';
  // Regenerating an expired credential is refused by the server (the new
  // secret could never verify), so the action only shows while active.
  const canRegenerate = credential.effectiveStatus === 'active';

  return (
    <>
      <tr className="border-b border-hairline-soft">
        <td className="py-2.5 pr-1 align-top">
          <button
            onClick={onToggleExpand}
            className="text-faint hover:text-ink-mid mt-0.5"
            aria-label={expanded ? 'Collapse bound accounts' : 'Show bound accounts'}
          >
            {expanded ? (
              <ChevronDown className="h-4 w-4" />
            ) : (
              <ChevronRight className="h-4 w-4" />
            )}
          </button>
        </td>
        <td className="py-2.5 pr-3 align-top">
          <div className="font-medium text-ink">{credential.name}</div>
          {credential.adPrincipal && (
            <div
              className="text-xs text-muted mt-0.5"
              title={credential.adPrincipal.sid}
            >
              Owner: {credential.adPrincipal.name} ({credential.adPrincipal.type})
            </div>
          )}
        </td>
        <td className="py-2.5 pr-3 align-top">
          <span className="inline-flex items-center gap-1.5 font-mono text-xs text-ink-soft">
            {credential.keyId}
            <CopyButton value={credential.keyId} label={`key ID of ${credential.name}`} />
          </span>
        </td>
        <td className="py-2.5 pr-3 align-top">
          <span
            className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${statusColors[credential.effectiveStatus]}`}
          >
            {credential.effectiveStatus}
          </span>
        </td>
        <td className="py-2.5 pr-3 align-top">
          {credential.namespaces.length === 0 ? (
            <span
              className="text-xs text-faint"
              title="No namespace: accounts may order for any domain the server allows."
            >
              any domain
            </span>
          ) : (
            <div className="flex flex-wrap gap-1 max-w-[16rem]">
              {credential.namespaces.map((entry) => (
                <span
                  key={entry}
                  className="inline-flex px-1.5 py-0.5 bg-sunken-strong rounded font-mono text-xs text-ink-soft"
                  title={`${entry} and its subdomains`}
                >
                  {entry}
                </span>
              ))}
            </div>
          )}
        </td>
        <td className="py-2.5 pr-3 align-top text-ink-soft tabular-nums">
          {credential.boundAccountCount}
        </td>
        <td className="py-2.5 pr-3 align-top text-muted whitespace-nowrap">
          {credential.expiresAt ? formatDate(credential.expiresAt) : '—'}
        </td>
        <td className="py-2.5 pr-3 align-top text-muted whitespace-nowrap">
          {formatDate(credential.createdAt)}
        </td>
        <td className="py-2.5 align-top text-right whitespace-nowrap">
          {busy ? (
            <Loader2 className="h-4 w-4 animate-spin inline text-faint" />
          ) : confirm ? (
            <span className="inline-flex items-center gap-2 text-xs">
              <span className="text-ink-mid">
                {confirm === 'revoke'
                  ? 'Revoke? Bound accounts stop ordering.'
                  : 'Regenerate? The current secret stops working.'}
              </span>
              <button
                onClick={confirm === 'revoke' ? onRevoke : onRegenerate}
                className={`font-semibold ${confirm === 'revoke' ? 'text-red-600 hover:text-red-800 dark:text-red-300' : 'text-certus-700 dark:text-certus-300 hover:text-certus-900 dark:text-certus-200'}`}
              >
                Confirm
              </button>
              <button
                onClick={() => onConfirmChange(null)}
                className="text-muted hover:text-ink-soft"
              >
                Cancel
              </button>
            </span>
          ) : (
            <span className="inline-flex items-center gap-3 text-xs font-medium">
              {!revoked && (
                <>
                  <button
                    onClick={() => onSetupChange(!showingSetup)}
                    className="inline-flex items-center gap-1 text-ink-mid hover:text-ink"
                  >
                    <Terminal className="h-3 w-3" />
                    Client setup
                  </button>
                  <button
                    onClick={() => onEditChange(!editing)}
                    className="inline-flex items-center gap-1 text-ink-mid hover:text-ink"
                  >
                    <Pencil className="h-3 w-3" />
                    Edit
                  </button>
                  {canRegenerate && (
                    <button
                      onClick={() => onConfirmChange('regenerate')}
                      className="text-certus-700 dark:text-certus-300 hover:text-certus-900 dark:text-certus-200"
                    >
                      Regenerate
                    </button>
                  )}
                  <button
                    onClick={() => onConfirmChange('revoke')}
                    className="text-red-600 hover:text-red-800 dark:text-red-300"
                  >
                    Revoke
                  </button>
                </>
              )}
              {revoked && credential.revokedAt && (
                <span className="text-faint font-normal">
                  revoked {formatDate(credential.revokedAt)}
                </span>
              )}
            </span>
          )}
        </td>
      </tr>
      {showingSetup && (
        <tr className="border-b border-hairline-soft bg-sunken">
          <td />
          <td colSpan={8} className="py-3 pr-3">
            <EabClientSnippets keyId={credential.keyId} secret={null} />
          </td>
        </tr>
      )}
      {editing && (
        <tr className="border-b border-hairline-soft bg-sunken">
          <td />
          <td colSpan={8} className="py-3 pr-3">
            <CredentialEditPanel
              credential={credential}
              onSaved={onEditSaved}
              onCancel={() => onEditChange(false)}
            />
          </td>
        </tr>
      )}
      {expanded && (
        <tr className="border-b border-hairline-soft bg-sunken">
          <td />
          <td colSpan={8} className="py-3 pr-3">
            <BoundAccountsList credentialId={credential.id} />
          </td>
        </tr>
      )}
    </>
  );
}

/**
 * The inline row editor: a full replacement of the name, expiry, and domain
 * namespace, plus the owner link. The key id and secret are untouched, and
 * a save is in force for the next ACME request. Saving an expired
 * credential with a future expiry (or none) puts it back in use, so the
 * panel says so. An owner only save skips the field replacement entirely:
 * that keeps it one request, and it is what lets an expired credential be
 * annotated without touching the expiry that suspends it.
 */
function CredentialEditPanel({
  credential,
  onSaved,
  onCancel,
}: {
  credential: EabCredentialSummary;
  onSaved: () => Promise<void>;
  onCancel: () => void;
}) {
  const queryClient = useQueryClient();
  const [name, setName] = useState(credential.name);
  // The stored instant as the input renders it, kept so an untouched field
  // round-trips the exact stored value: datetime-local carries no seconds,
  // and re-encoding an untouched value would silently truncate them.
  const initialExpiry = credential.expiresAt
    ? toDatetimeLocalValue(credential.expiresAt)
    : '';
  const [expiry, setExpiry] = useState(initialExpiry);
  const [domains, setDomains] = useState<string[]>(credential.namespaces);
  const [owner, setOwner] = useState<EabCredentialPrincipal | null>(
    credential.adPrincipal ?? null,
  );
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [invalidEntries, setInvalidEntries] = useState<InvalidDomainEntry[]>([]);

  const handleSave = async () => {
    setError(null);
    setInvalidEntries([]);
    const fieldsChanged =
      name.trim() !== credential.name ||
      expiry !== initialExpiry ||
      !sameEntries(domains, credential.namespaces);
    const ownerChanged =
      (owner?.sid ?? null) !== (credential.adPrincipal?.sid ?? null);
    // The server refuses a past expiry, and an expired credential prefills
    // one, so name the choices here instead of a round trip to a bare 400.
    // Only a field save trips this; an owner only save never touches the
    // expiry, so an expired credential can be annotated without reviving it.
    if (fieldsChanged && expiry && new Date(expiry).getTime() <= Date.now()) {
      setError(
        'The expiry is in the past. Set a future date, clear the field to ' +
        'remove the expiry, or revoke the credential to keep it unusable.',
      );
      return;
    }
    setSaving(true);
    try {
      if (fieldsChanged) {
        const expiresAt =
          expiry === ''
            ? null
            : expiry === initialExpiry
              ? credential.expiresAt ?? null
              : new Date(expiry).toISOString();
        const outcome = await updateEabCredential(
          credential.id, name.trim(), expiresAt, domains);
        if (outcome.kind === 'invalid') {
          setError(outcome.error);
          setInvalidEntries(outcome.invalidEntries);
          return;
        }
      }
      // The owner link rides its own endpoint pair (the server re-resolves
      // the SID before storing), so it saves after the fields. If it fails
      // here, any fields above are already saved: refresh the list so the
      // table and cache show them (otherwise reopening Edit would seed from
      // stale rows and a later save would silently revert them), and say
      // exactly what failed. Pressing Save again retries only the owner,
      // because the refreshed row makes the fields read as unchanged.
      if (ownerChanged) {
        try {
          if (owner === null) {
            await clearEabCredentialPrincipal(credential.id);
          } else {
            await setEabCredentialPrincipal(credential.id, owner.sid);
          }
        } catch (err) {
          const reason = err instanceof Error ? err.message : 'unknown error';
          if (fieldsChanged) {
            await queryClient.invalidateQueries({
              queryKey: ['acme', 'eab-credentials'], exact: true });
            setError(
              `The name, expiry, and namespace were saved, but the owner change was not: ${reason}`,
            );
          } else {
            setError(`The owner change was not saved: ${reason}`);
          }
          return;
        }
      }
      await onSaved();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Saving failed');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-3">
      <p className="text-xs font-semibold text-ink-soft">
        Edit "{credential.name}"
        <span className="ml-2 font-normal text-muted">
          The key id and secret stay; changes apply to new ACME requests
          immediately.
        </span>
      </p>
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
        <div>
          <label className="block text-xs font-medium text-ink-mid mb-1">Name</label>
          <input
            type="text"
            value={name}
            onChange={(e) => setName(e.target.value)}
            maxLength={200}
            className="w-full px-3 py-2 bg-surface border border-hairline-strong rounded-lg text-sm
                       placeholder:text-faint focus:outline-none focus:ring-2
                       focus:ring-certus-500 focus:border-certus-500"
          />
        </div>
        <div>
          <label className="block text-xs font-medium text-ink-mid mb-1">
            Expiry (optional)
          </label>
          <input
            type="datetime-local"
            value={expiry}
            onChange={(e) => setExpiry(e.target.value)}
            className="w-full px-3 py-2 bg-surface border border-hairline-strong rounded-lg text-sm
                       text-ink-soft focus:outline-none focus:ring-2
                       focus:ring-certus-500 focus:border-certus-500"
          />
        </div>
      </div>
      <div>
        <label className="block text-xs font-medium text-ink-mid mb-1">
          Domain namespace
        </label>
        <DomainListEditor
          domains={domains}
          onAdd={(domain) => {
            setError(null);
            setInvalidEntries([]);
            if (!domains.includes(domain)) setDomains([...domains, domain]);
          }}
          onRemove={(domain) => setDomains(domains.filter((d) => d !== domain))}
          emptyText="No namespace. Accounts using this credential may order for any domain the server allows."
        />
      </div>
      <div>
        <label className="block text-xs font-medium text-ink-mid mb-1">
          Owner (optional)
        </label>
        <PrincipalPicker value={owner} onChange={setOwner} />
        <p className="text-xs text-faint mt-1">
          The directory account this credential was issued to, shown on the
          credential row. For display and audit only; it does not change
          what the credential may do.
        </p>
      </div>
      {credential.effectiveStatus === 'expired' && (
        <div className="bg-amber-50 dark:bg-amber-500/10 border border-amber-200 dark:border-amber-500/30 rounded-lg p-3 flex items-start gap-2">
          <AlertTriangle className="h-4 w-4 text-amber-600 mt-0.5" />
          <p className="text-xs text-amber-800 dark:text-amber-300">
            This credential is expired. Saving with a future expiry, or with
            no expiry, puts it and its accounts back in use. To keep it
            unusable for good, revoke it instead.
          </p>
        </div>
      )}
      {error && <EntryErrors error={error} invalidEntries={invalidEntries} />}
      <div className="flex items-center justify-end gap-2">
        <button
          onClick={onCancel}
          className="px-4 py-2 text-sm font-medium text-ink-mid hover:text-ink-strong"
        >
          Cancel
        </button>
        <button
          onClick={handleSave}
          disabled={saving || name.trim().length === 0}
          className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium text-white
                     bg-certus-600 rounded-lg hover:bg-certus-700 disabled:opacity-50
                     transition-colors"
        >
          {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Save'}
        </button>
      </div>
    </div>
  );
}

/** The red error block, with the per entry namespace reasons when a save
 * was refused because of them (the settings card idiom). */
function EntryErrors({
  error,
  invalidEntries,
}: {
  error: string;
  invalidEntries: InvalidDomainEntry[];
}) {
  return (
    <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/30 rounded-lg p-3 flex items-start gap-2">
      <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5" />
      <div className="space-y-1">
        <p className="text-xs text-red-700 dark:text-red-300">{error}</p>
        {invalidEntries.length > 0 && (
          <ul className="text-xs text-red-700 dark:text-red-300 list-disc list-inside space-y-0.5">
            {invalidEntries.map((entry) => (
              <li key={entry.entry}>
                <code className="font-mono">{entry.entry}</code>: {entry.reason}
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

/** Set equality for normalized namespace lists; entry order is irrelevant. */
function sameEntries(a: string[], b: string[]): boolean {
  return a.length === b.length && a.every((entry) => b.includes(entry));
}

/** An ISO instant as the local wall clock value a datetime-local input wants. */
function toDatetimeLocalValue(iso: string): string {
  const date = new Date(iso);
  const pad = (n: number) => String(n).padStart(2, '0');
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())}`
    + `T${pad(date.getHours())}:${pad(date.getMinutes())}`;
}

function BoundAccountsList({ credentialId }: { credentialId: number }) {
  const { data: accounts, isLoading, isError } = useQuery({
    queryKey: ['acme', 'eab-credentials', credentialId, 'accounts'],
    queryFn: () => fetchEabBoundAccounts(credentialId),
    staleTime: 30_000,
    retry: false,
  });

  if (isLoading) {
    return (
      <div className="flex items-center gap-2 text-xs text-faint">
        <Loader2 className="h-3.5 w-3.5 animate-spin" />
        Loading bound accounts…
      </div>
    );
  }
  if (isError) {
    return <p className="text-xs text-red-700 dark:text-red-300">The bound accounts could not be loaded.</p>;
  }
  if ((accounts ?? []).length === 0) {
    return (
      <p className="text-xs text-muted">
        No accounts are bound to this credential yet. An account binds when an
        ACME client registers with this key id and secret.
      </p>
    );
  }
  return (
    <ul className="space-y-1">
      {(accounts ?? []).map((account) => (
        <li key={account.id} className="text-xs text-ink-soft flex items-center gap-3">
          <span className="font-mono">{account.accountId}</span>
          <span className={account.status === 'valid' ? 'text-emerald-700 dark:text-emerald-300' : 'text-faint'}>
            {account.status}
          </span>
          {account.contacts && account.contacts.length > 0 && (
            <span className="text-muted">{account.contacts.join(', ')}</span>
          )}
          <span className="text-faint">registered {formatDateTime(account.createdAt)}</span>
        </li>
      ))}
    </ul>
  );
}
