import { useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import {
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  Loader2,
  Lock,
  Pencil,
  Plus,
  ShieldCheck,
  Smartphone,
} from 'lucide-react';
import {
  addAllowlistEntry,
  addTrustAnchor,
  createDeviceProfile,
  deleteAllowlistEntry,
  deleteDeviceProfile,
  deleteTrustAnchor,
  fetchAllowlist,
  fetchDeviceProfiles,
  fetchTrustAnchors,
  updateAllowlistEntry,
  updateDeviceProfile,
  type CsrIdentifierBinding,
  type DeviceGateMode,
  type DeviceProfile,
} from '@/api/deviceAttestation';
import { fetchTemplates } from '@/api/client';
import { CopyButton } from '@/components/CopyButton';
import { formatDate } from '@/types';

const gateModeLabels: Record<DeviceGateMode, string> = {
  allowlist: 'Allowlist',
  open: 'Open (observation)',
};

const bindingLabels: Record<CsrIdentifierBinding, string> = {
  'cn-or-san': 'CN or SAN',
  'san-required': 'SAN required',
  none: 'None (privacy)',
};

/**
 * Dashboard card for ACME device-attest-01 (draft-ietf-acme-device-attest-08).
 * A profile is the explicit act that turns the feature on for one template:
 * with no profile, a permanent-identifier order answers the same refusal a
 * server without the feature returns. Allowlist mode admits only listed
 * devices (fail closed); open mode admits any device that passes attestation.
 * Every change here applies to the next device order with no restart. The
 * trust anchor panel below manages the roots attestation chains verify against.
 */
export function DeviceAttestationCard() {
  const queryClient = useQueryClient();

  const { data: profiles, isLoading, isError } = useQuery({
    queryKey: ['acme', 'device-profiles'],
    queryFn: fetchDeviceProfiles,
    staleTime: 30_000,
    retry: false,
  });

  const [formOpen, setFormOpen] = useState(false);
  const [expandedId, setExpandedId] = useState<number | null>(null);
  const [editId, setEditId] = useState<number | null>(null);
  const [confirmDeleteId, setConfirmDeleteId] = useState<number | null>(null);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);

  const refresh = () =>
    queryClient.invalidateQueries({ queryKey: ['acme', 'device-profiles'], exact: true });

  const handleDelete = async (id: number) => {
    setBusyId(id);
    setActionError(null);
    setConfirmDeleteId(null);
    try {
      await deleteDeviceProfile(id);
      setEditId((open) => (open === id ? null : open));
      setExpandedId((open) => (open === id ? null : open));
      await refresh();
    } catch (err) {
      setActionError(err instanceof Error ? err.message : 'Delete failed');
    } finally {
      setBusyId(null);
    }
  };

  return (
    <div className="bg-surface border border-hairline rounded-lg p-6 space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Smartphone className="h-4 w-4 text-certus-600" />
          <h3 className="text-sm font-semibold text-ink">Device Attestation</h3>
        </div>
        <button
          onClick={() => {
            setFormOpen(!formOpen);
            setActionError(null);
          }}
          className="inline-flex items-center gap-2 px-3 py-1.5 text-sm font-medium
                     text-certus-700 dark:text-certus-300 bg-certus-50 dark:bg-certus-500/10 border border-certus-200 dark:border-certus-500/30 rounded-lg
                     hover:bg-certus-100 dark:bg-certus-500/15 transition-colors"
        >
          <Plus className="h-4 w-4" />
          New profile
        </button>
      </div>
      <p className="text-sm text-muted">
        A profile turns ACME device-attest-01 on for one certificate template.
        Apple Managed Device Attestation is the supported client. Allowlist mode
        admits only the device serials you list; open mode admits any device
        whose attestation verifies, for observation. Without a profile a
        template does not offer device orders at all.
      </p>

      {formOpen && (
        <ProfileForm
          profiles={profiles ?? []}
          onSaved={async () => {
            setFormOpen(false);
            await refresh();
          }}
          onCancel={() => setFormOpen(false)}
        />
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
          Loading profiles…
        </div>
      ) : isError ? (
        <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/30 rounded-lg p-3 flex items-start gap-2">
          <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5" />
          <p className="text-xs text-red-700 dark:text-red-300">The profiles could not be loaded.</p>
        </div>
      ) : (profiles ?? []).length === 0 ? (
        <p className="text-sm text-faint py-2">
          No profiles yet. Create one to enable device certificate issuance on a
          template.
        </p>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-left text-xs text-muted uppercase border-b border-hairline">
                <th className="py-2 pr-3 font-medium" />
                <th className="py-2 pr-3 font-medium">Template</th>
                <th className="py-2 pr-3 font-medium">Status</th>
                <th className="py-2 pr-3 font-medium">Gate mode</th>
                <th className="py-2 pr-3 font-medium">CSR binding</th>
                <th className="py-2 pr-3 font-medium">Devices</th>
                <th className="py-2 font-medium text-right">Actions</th>
              </tr>
            </thead>
            <tbody>
              {(profiles ?? []).map((profile) => (
                <ProfileRow
                  key={profile.id}
                  profile={profile}
                  expanded={expandedId === profile.id}
                  onToggleExpand={() =>
                    setExpandedId(expandedId === profile.id ? null : profile.id)
                  }
                  editing={editId === profile.id}
                  onEditChange={(on) => setEditId(on ? profile.id : null)}
                  onEditSaved={async () => {
                    setEditId(null);
                    await refresh();
                  }}
                  confirmingDelete={confirmDeleteId === profile.id}
                  onConfirmDeleteChange={(on) =>
                    setConfirmDeleteId(on ? profile.id : null)
                  }
                  busy={busyId === profile.id}
                  onDelete={() => handleDelete(profile.id)}
                />
              ))}
            </tbody>
          </table>
        </div>
      )}

      <TrustAnchorsPanel />
    </div>
  );
}

function ProfileRow({
  profile,
  expanded,
  onToggleExpand,
  editing,
  onEditChange,
  onEditSaved,
  confirmingDelete,
  onConfirmDeleteChange,
  busy,
  onDelete,
}: {
  profile: DeviceProfile;
  expanded: boolean;
  onToggleExpand: () => void;
  editing: boolean;
  onEditChange: (on: boolean) => void;
  onEditSaved: () => Promise<void>;
  confirmingDelete: boolean;
  onConfirmDeleteChange: (on: boolean) => void;
  busy: boolean;
  onDelete: () => void;
}) {
  return (
    <>
      <tr className="border-b border-hairline-soft">
        <td className="py-2.5 pr-1 align-top">
          <button
            onClick={onToggleExpand}
            className="text-faint hover:text-ink-mid mt-0.5"
            aria-label={expanded ? 'Collapse allowlist' : 'Show allowlist'}
          >
            {expanded ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
          </button>
        </td>
        <td className="py-2.5 pr-3 align-top font-medium text-ink">
          {profile.templateId}
        </td>
        <td className="py-2.5 pr-3 align-top">
          <span
            className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${
              profile.enabled
                ? 'bg-emerald-100 dark:bg-emerald-500/15 text-emerald-800 dark:text-emerald-300'
                : 'bg-sunken-strong text-ink-mid'
            }`}
          >
            {profile.enabled ? 'enabled' : 'disabled'}
          </span>
        </td>
        <td className="py-2.5 pr-3 align-top text-ink-soft">
          {gateModeLabels[profile.gateMode]}
        </td>
        <td className="py-2.5 pr-3 align-top text-ink-soft">
          {bindingLabels[profile.csrIdentifierBinding]}
        </td>
        <td className="py-2.5 pr-3 align-top text-ink-soft tabular-nums">
          {profile.gateMode === 'open' ? (
            <span className="text-faint" title="Open mode admits any attested device">
              any
            </span>
          ) : (
            profile.allowlistCount
          )}
        </td>
        <td className="py-2.5 align-top text-right whitespace-nowrap">
          {busy ? (
            <Loader2 className="h-4 w-4 animate-spin inline text-faint" />
          ) : confirmingDelete ? (
            <span className="inline-flex items-center gap-2 text-xs">
              <span className="text-ink-mid">Delete? Device orders stop.</span>
              <button
                onClick={onDelete}
                className="font-semibold text-red-600 hover:text-red-800 dark:text-red-300"
              >
                Confirm
              </button>
              <button
                onClick={() => onConfirmDeleteChange(false)}
                className="text-muted hover:text-ink-soft"
              >
                Cancel
              </button>
            </span>
          ) : (
            <span className="inline-flex items-center gap-3 text-xs font-medium">
              <button
                onClick={() => onEditChange(!editing)}
                className="inline-flex items-center gap-1 text-ink-mid hover:text-ink"
              >
                <Pencil className="h-3 w-3" />
                Edit
              </button>
              <button
                onClick={() => onConfirmDeleteChange(true)}
                className="text-red-600 hover:text-red-800 dark:text-red-300"
              >
                Delete
              </button>
            </span>
          )}
        </td>
      </tr>
      {editing && (
        <tr className="border-b border-hairline-soft bg-sunken">
          <td />
          <td colSpan={6} className="py-3 pr-3">
            <ProfileForm
              profiles={[]}
              editing={profile}
              onSaved={onEditSaved}
              onCancel={() => onEditChange(false)}
            />
          </td>
        </tr>
      )}
      {expanded && (
        <tr className="border-b border-hairline-soft bg-sunken">
          <td />
          <td colSpan={6} className="py-3 pr-3">
            {profile.gateMode === 'open' ? (
              <p className="text-xs text-muted">
                This profile is in open mode: any device whose attestation
                verifies is admitted, so there is no allowlist. Switch to
                allowlist mode to restrict issuance to named devices.
              </p>
            ) : (
              <AllowlistEditor profileId={profile.id} />
            )}
          </td>
        </tr>
      )}
    </>
  );
}

/**
 * The create and edit form. On create it offers a template picker (only
 * templates without a profile, since there is one profile per template); on
 * edit the template is fixed and only the modes and enabled flag change.
 */
function ProfileForm({
  profiles,
  editing,
  onSaved,
  onCancel,
}: {
  profiles: DeviceProfile[];
  editing?: DeviceProfile;
  onSaved: () => Promise<void>;
  onCancel: () => void;
}) {
  const { data: templates, isError: templatesError } = useQuery({
    queryKey: ['acme', 'device-templates'],
    queryFn: fetchTemplates,
    staleTime: 60_000,
    retry: false,
    enabled: !editing,
  });

  const taken = new Set(profiles.map((p) => p.templateId));
  const available = (templates ?? []).filter((t) => !taken.has(t.name));

  const [templateId, setTemplateId] = useState(editing?.templateId ?? '');
  const [gateMode, setGateMode] = useState<DeviceGateMode>(editing?.gateMode ?? 'allowlist');
  const [binding, setBinding] = useState<CsrIdentifierBinding>(
    editing?.csrIdentifierBinding ?? 'cn-or-san');
  const [enabled, setEnabled] = useState(editing?.enabled ?? true);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSave = async () => {
    setError(null);
    if (!editing && templateId === '') {
      setError('Choose a template.');
      return;
    }
    setSaving(true);
    try {
      if (editing) {
        await updateDeviceProfile(editing.id, { gateMode, csrIdentifierBinding: binding, enabled });
      } else {
        await createDeviceProfile({ templateId, gateMode, csrIdentifierBinding: binding, enabled });
      }
      await onSaved();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Saving failed');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="border border-hairline rounded-lg p-4 space-y-3 bg-sunken">
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        <div>
          <label className="block text-xs font-medium text-ink-mid mb-1">Template</label>
          {editing ? (
            <div className="px-3 py-2 text-sm text-ink-soft font-medium">
              {editing.templateId}
            </div>
          ) : templatesError ? (
            <p className="text-xs text-red-600 py-2">Could not load templates from the CA.</p>
          ) : available.length === 0 ? (
            <p className="text-xs text-muted py-2">
              Every enabled template already has a profile.
            </p>
          ) : (
            <select
              value={templateId}
              onChange={(e) => setTemplateId(e.target.value)}
              className="w-full px-3 py-2 bg-surface border border-hairline-strong rounded-lg text-sm
                         text-ink-soft focus:outline-none focus:ring-2 focus:ring-certus-500"
            >
              <option value="">Select a template…</option>
              {available.map((t) => (
                <option key={t.name} value={t.name}>
                  {t.displayName}
                </option>
              ))}
            </select>
          )}
        </div>
        <div>
          <label className="block text-xs font-medium text-ink-mid mb-1">Gate mode</label>
          <select
            value={gateMode}
            onChange={(e) => setGateMode(e.target.value as DeviceGateMode)}
            className="w-full px-3 py-2 bg-surface border border-hairline-strong rounded-lg text-sm
                       text-ink-soft focus:outline-none focus:ring-2 focus:ring-certus-500"
          >
            <option value="allowlist">Allowlist (fail closed)</option>
            <option value="open">Open (observation)</option>
          </select>
        </div>
        <div>
          <label className="block text-xs font-medium text-ink-mid mb-1">CSR binding</label>
          <select
            value={binding}
            onChange={(e) => setBinding(e.target.value as CsrIdentifierBinding)}
            className="w-full px-3 py-2 bg-surface border border-hairline-strong rounded-lg text-sm
                       text-ink-soft focus:outline-none focus:ring-2 focus:ring-certus-500"
          >
            <option value="cn-or-san">CN or SAN (default)</option>
            <option value="san-required">SAN required</option>
            <option value="none">None (privacy)</option>
          </select>
        </div>
      </div>
      <label className="flex items-center gap-2 text-sm text-ink-soft">
        <input
          type="checkbox"
          checked={enabled}
          onChange={(e) => setEnabled(e.target.checked)}
          className="rounded border-hairline-strong text-certus-600 focus:ring-certus-500"
        />
        Enabled (a disabled profile refuses device orders but keeps its allowlist)
      </label>
      {error && (
        <div className="bg-red-50 dark:bg-red-500/10 border border-red-200 dark:border-red-500/30 rounded-lg p-3 flex items-start gap-2">
          <AlertTriangle className="h-4 w-4 text-red-500 mt-0.5" />
          <p className="text-xs text-red-700 dark:text-red-300">{error}</p>
        </div>
      )}
      <div className="flex items-center justify-end gap-2">
        <button
          onClick={onCancel}
          className="px-4 py-2 text-sm font-medium text-ink-mid hover:text-ink-strong"
        >
          Cancel
        </button>
        <button
          onClick={handleSave}
          disabled={saving}
          className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium text-white
                     bg-certus-600 rounded-lg hover:bg-certus-700 disabled:opacity-50
                     transition-colors"
        >
          {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : editing ? 'Save' : 'Create'}
        </button>
      </div>
    </div>
  );
}

/** The allowlist editor for one profile: add, edit, and remove device entries. */
function AllowlistEditor({ profileId }: { profileId: number }) {
  const queryClient = useQueryClient();
  const { data: entries, isLoading, isError } = useQuery({
    queryKey: ['acme', 'device-allowlist', profileId],
    queryFn: () => fetchAllowlist(profileId),
    staleTime: 30_000,
    retry: false,
  });

  const [value, setValue] = useState('');
  const [note, setNote] = useState('');
  const [adding, setAdding] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirmRemoveId, setConfirmRemoveId] = useState<number | null>(null);
  const [editId, setEditId] = useState<number | null>(null);

  const refresh = () => {
    // The device count on the profile row changes with the allowlist, so
    // refresh the profile list too.
    queryClient.invalidateQueries({ queryKey: ['acme', 'device-allowlist', profileId] });
    queryClient.invalidateQueries({ queryKey: ['acme', 'device-profiles'], exact: true });
  };

  const handleAdd = async () => {
    setError(null);
    setAdding(true);
    try {
      await addAllowlistEntry(profileId, value.trim(), note.trim() || undefined);
      setValue('');
      setNote('');
      refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Adding failed');
    } finally {
      setAdding(false);
    }
  };

  const handleRemove = async (entryId: number) => {
    setError(null);
    setConfirmRemoveId(null);
    try {
      await deleteAllowlistEntry(entryId);
      refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Removing failed');
    }
  };

  return (
    <div className="space-y-3">
      <p className="text-xs font-semibold text-ink-soft">Allowlisted devices</p>

      <div className="flex flex-wrap items-end gap-2">
        <div className="flex-1 min-w-[12rem]">
          <label className="block text-xs font-medium text-ink-mid mb-1">
            Serial or UDID
          </label>
          <input
            type="text"
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder="e.g. F2LW80XYZ123"
            maxLength={253}
            className="w-full px-3 py-2 bg-surface border border-hairline-strong rounded-lg text-sm
                       placeholder:text-faint focus:outline-none focus:ring-2 focus:ring-certus-500"
          />
        </div>
        <div className="flex-1 min-w-[10rem]">
          <label className="block text-xs font-medium text-ink-mid mb-1">Note (optional)</label>
          <input
            type="text"
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder="asset tag, owner"
            maxLength={500}
            className="w-full px-3 py-2 bg-surface border border-hairline-strong rounded-lg text-sm
                       placeholder:text-faint focus:outline-none focus:ring-2 focus:ring-certus-500"
          />
        </div>
        <button
          onClick={handleAdd}
          disabled={adding || value.trim().length === 0}
          className="inline-flex items-center gap-2 px-3 py-2 text-sm font-medium text-white
                     bg-certus-600 rounded-lg hover:bg-certus-700 disabled:opacity-50 transition-colors"
        >
          {adding ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />}
          Add
        </button>
      </div>

      {error && <p className="text-xs text-red-700 dark:text-red-300">{error}</p>}

      {isLoading ? (
        <div className="flex items-center gap-2 text-xs text-faint">
          <Loader2 className="h-3.5 w-3.5 animate-spin" />
          Loading devices…
        </div>
      ) : isError ? (
        <p className="text-xs text-red-700 dark:text-red-300">The allowlist could not be loaded.</p>
      ) : (entries ?? []).length === 0 ? (
        <p className="text-xs text-muted">
          No devices yet. In allowlist mode, no device can order until it is
          listed here.
        </p>
      ) : editId !== null ? null : (
        <ul className="space-y-1">
          {(entries ?? []).map((entry) => (
            <li key={entry.id} className="flex items-center gap-3 text-xs text-ink-soft">
              <span className="font-mono">{entry.identifierValue}</span>
              {entry.note && <span className="text-muted">{entry.note}</span>}
              <span className="text-faint">added {formatDate(entry.createdAt)}</span>
              <span className="ml-auto inline-flex items-center gap-3">
                <button
                  onClick={() => setEditId(entry.id)}
                  className="text-muted hover:text-ink-strong"
                >
                  Edit
                </button>
                {confirmRemoveId === entry.id ? (
                  <span className="inline-flex items-center gap-2">
                    <button
                      onClick={() => handleRemove(entry.id)}
                      className="font-semibold text-red-600 hover:text-red-800 dark:text-red-300"
                    >
                      Confirm
                    </button>
                    <button
                      onClick={() => setConfirmRemoveId(null)}
                      className="text-muted hover:text-ink-soft"
                    >
                      Cancel
                    </button>
                  </span>
                ) : (
                  <button
                    onClick={() => setConfirmRemoveId(entry.id)}
                    className="text-red-600 hover:text-red-800 dark:text-red-300"
                  >
                    Remove
                  </button>
                )}
              </span>
            </li>
          ))}
        </ul>
      )}

      {editId !== null && (
        <AllowlistEntryEditor
          entry={(entries ?? []).find((e) => e.id === editId)!}
          onSaved={() => {
            setEditId(null);
            refresh();
          }}
          onCancel={() => setEditId(null)}
        />
      )}
    </div>
  );
}

/** Inline editor for one allowlist entry (its identifier value and note). */
function AllowlistEntryEditor({
  entry,
  onSaved,
  onCancel,
}: {
  entry: { id: number; identifierValue: string; note?: string | null };
  onSaved: () => void;
  onCancel: () => void;
}) {
  const [value, setValue] = useState(entry.identifierValue);
  const [note, setNote] = useState(entry.note ?? '');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleSave = async () => {
    setError(null);
    setSaving(true);
    try {
      await updateAllowlistEntry(entry.id, value.trim(), note.trim() || undefined);
      onSaved();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Saving failed');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="flex flex-wrap items-end gap-2 border border-hairline rounded-lg p-3 bg-surface">
      <div className="flex-1 min-w-[12rem]">
        <label className="block text-xs font-medium text-ink-mid mb-1">Serial or UDID</label>
        <input
          type="text"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          maxLength={253}
          className="w-full px-3 py-2 bg-surface border border-hairline-strong rounded-lg text-sm
                     focus:outline-none focus:ring-2 focus:ring-certus-500"
        />
      </div>
      <div className="flex-1 min-w-[10rem]">
        <label className="block text-xs font-medium text-ink-mid mb-1">Note</label>
        <input
          type="text"
          value={note}
          onChange={(e) => setNote(e.target.value)}
          maxLength={500}
          className="w-full px-3 py-2 bg-surface border border-hairline-strong rounded-lg text-sm
                     focus:outline-none focus:ring-2 focus:ring-certus-500"
        />
      </div>
      <button
        onClick={handleSave}
        disabled={saving || value.trim().length === 0}
        className="inline-flex items-center gap-2 px-3 py-2 text-sm font-medium text-white
                   bg-certus-600 rounded-lg hover:bg-certus-700 disabled:opacity-50 transition-colors"
      >
        {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Save'}
      </button>
      <button
        onClick={onCancel}
        className="px-3 py-2 text-sm font-medium text-ink-mid hover:text-ink-strong"
      >
        Cancel
      </button>
      {error && <p className="w-full text-xs text-red-700 dark:text-red-300">{error}</p>}
    </div>
  );
}

/**
 * The trust anchor panel: the roots attestation chains verify against. Built
 * in roots (the pinned vendor roots this build ships) are read only; custom
 * anchors are additive, for bridging a vendor root rotation or injecting a
 * test root.
 */
function TrustAnchorsPanel() {
  const queryClient = useQueryClient();
  const { data: anchors, isLoading, isError } = useQuery({
    queryKey: ['acme', 'device-anchors'],
    queryFn: fetchTrustAnchors,
    staleTime: 30_000,
    retry: false,
  });

  const [formOpen, setFormOpen] = useState(false);
  const [name, setName] = useState('');
  const [pem, setPem] = useState('');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [confirmRemoveId, setConfirmRemoveId] = useState<number | null>(null);

  const refresh = () =>
    queryClient.invalidateQueries({ queryKey: ['acme', 'device-anchors'], exact: true });

  const handleAdd = async () => {
    setError(null);
    setSaving(true);
    try {
      // Apple is the only supported format in this build; the format select is
      // fixed until another verifier ships.
      await addTrustAnchor({ format: 'apple', name: name.trim(), certificatePem: pem.trim() });
      setName('');
      setPem('');
      setFormOpen(false);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Adding failed');
    } finally {
      setSaving(false);
    }
  };

  const handleRemove = async (id: number) => {
    setError(null);
    setConfirmRemoveId(null);
    try {
      await deleteTrustAnchor(id);
      await refresh();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Removing failed');
    }
  };

  return (
    <div className="border-t border-hairline pt-4 space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <ShieldCheck className="h-4 w-4 text-certus-600" />
          <h4 className="text-sm font-semibold text-ink">Trust anchors</h4>
        </div>
        <button
          onClick={() => {
            setFormOpen(!formOpen);
            setError(null);
          }}
          className="inline-flex items-center gap-2 px-3 py-1.5 text-xs font-medium
                     text-certus-700 dark:text-certus-300 bg-certus-50 dark:bg-certus-500/10 border border-certus-200 dark:border-certus-500/30 rounded-lg
                     hover:bg-certus-100 dark:bg-certus-500/15 transition-colors"
        >
          <Plus className="h-3.5 w-3.5" />
          Add anchor
        </button>
      </div>
      <p className="text-xs text-muted">
        Attestation certificate chains must verify to one of these roots. The
        built in roots are pinned in this build and cannot be removed. Add a
        custom anchor to bridge a vendor root rotation before the pin updates,
        or to trust a test root.
      </p>

      {formOpen && (
        <div className="border border-hairline rounded-lg p-4 space-y-3 bg-sunken">
          <div>
            <label className="block text-xs font-medium text-ink-mid mb-1">Name</label>
            <input
              type="text"
              value={name}
              onChange={(e) => setName(e.target.value)}
              placeholder="e.g. Apple root 2025 rotation"
              maxLength={200}
              className="w-full px-3 py-2 bg-surface border border-hairline-strong rounded-lg text-sm
                         placeholder:text-faint focus:outline-none focus:ring-2 focus:ring-certus-500"
            />
          </div>
          <div>
            <label className="block text-xs font-medium text-ink-mid mb-1">
              Certificate (PEM), apple format
            </label>
            <textarea
              value={pem}
              onChange={(e) => setPem(e.target.value)}
              rows={5}
              placeholder="-----BEGIN CERTIFICATE-----"
              className="w-full px-3 py-2 bg-surface border border-hairline-strong rounded-lg text-xs font-mono
                         placeholder:text-faint focus:outline-none focus:ring-2 focus:ring-certus-500"
            />
          </div>
          {error && <p className="text-xs text-red-700 dark:text-red-300">{error}</p>}
          <div className="flex items-center justify-end gap-2">
            <button
              onClick={() => setFormOpen(false)}
              className="px-4 py-2 text-sm font-medium text-ink-mid hover:text-ink-strong"
            >
              Cancel
            </button>
            <button
              onClick={handleAdd}
              disabled={saving || name.trim().length === 0 || pem.trim().length === 0}
              className="inline-flex items-center gap-2 px-4 py-2 text-sm font-medium text-white
                         bg-certus-600 rounded-lg hover:bg-certus-700 disabled:opacity-50 transition-colors"
            >
              {saving ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Add'}
            </button>
          </div>
        </div>
      )}

      {!formOpen && error && <p className="text-xs text-red-700 dark:text-red-300">{error}</p>}

      {isLoading ? (
        <div className="flex items-center gap-2 text-xs text-faint">
          <Loader2 className="h-3.5 w-3.5 animate-spin" />
          Loading anchors…
        </div>
      ) : isError ? (
        <p className="text-xs text-red-700 dark:text-red-300">The trust anchors could not be loaded.</p>
      ) : (
        <ul className="space-y-1">
          {(anchors ?? []).map((anchor) => (
            <li
              key={anchor.builtIn ? `builtin-${anchor.sha256Fingerprint}` : `custom-${anchor.id}`}
              className="flex items-center gap-3 text-xs text-ink-soft"
            >
              {anchor.builtIn ? (
                <Lock className="h-3.5 w-3.5 text-faint" aria-label="Built in, read only" />
              ) : (
                <ShieldCheck className="h-3.5 w-3.5 text-emerald-500" />
              )}
              <span className="font-medium">{anchor.name}</span>
              <span className="uppercase text-faint">{anchor.format}</span>
              <span className="font-mono text-muted truncate max-w-[14rem]" title={anchor.sha256Fingerprint}>
                {anchor.sha256Fingerprint}
              </span>
              <CopyButton value={anchor.sha256Fingerprint} label="fingerprint" />
              {anchor.builtIn ? (
                <span className="ml-auto text-faint">built in</span>
              ) : (
                <span className="ml-auto">
                  {confirmRemoveId === anchor.id ? (
                    <span className="inline-flex items-center gap-2">
                      <button
                        onClick={() => handleRemove(anchor.id!)}
                        className="font-semibold text-red-600 hover:text-red-800 dark:text-red-300"
                      >
                        Confirm
                      </button>
                      <button
                        onClick={() => setConfirmRemoveId(null)}
                        className="text-muted hover:text-ink-soft"
                      >
                        Cancel
                      </button>
                    </span>
                  ) : (
                    <button
                      onClick={() => setConfirmRemoveId(anchor.id!)}
                      className="text-red-600 hover:text-red-800 dark:text-red-300"
                    >
                      Remove
                    </button>
                  )}
                </span>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
