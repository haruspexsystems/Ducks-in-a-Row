import type {
  LicenceDetails,
  LicenceInspectResponse,
  LicenceModule,
  LicenceStatusResponse,
} from '@/api/licence';

// What the licence card, the licence banner and the About block say, for every
// pair of module state and licence status (licence design section 13.3, issue
// #493). Pure functions, so every pair is tested in lib/licence.test.ts.
//
// Two rules hold throughout:
// - Nothing here reads the browser's clock. Days come from the server's
//   daysRemaining and dates are shown as given, so the banner can never
//   disagree with the server about how long is left (design section 9.1). The
//   HTTPS certificate banner does count days itself, and this must not copy it.
// - Every state that leaves paid features off, or warns, ends with NOT_AFFECTED.

/** The sentence every negative state ends with (design section 13.3). */
export const NOT_AFFECTED = 'Certificate issuance and renewal are not affected.';

/** The largest licence file the API accepts (LicenceController.MaxLicenceBytes). */
export const MAX_LICENCE_BYTES = 16_384;

/** What the CA limit claim holds when it means no practical limit (design section 7.3). */
const NO_CA_LIMIT = 999;

export type LicenceTone = 'neutral' | 'good' | 'amber' | 'red' | 'grey';

/** The tones that warn or say paid features are off, and so end with NOT_AFFECTED. */
export function isNegativeTone(tone: LicenceTone): boolean {
  return tone === 'amber' || tone === 'red' || tone === 'grey';
}

/**
 * Whether Retry applies: a module that failed, stopped answering, or was set
 * aside after failing twice. Mirrors ModuleStateExtensions.IsSetAside on the
 * server, which answers 409 for anything else. Incompatible and Refused are left
 * out on purpose, because a restart changes neither.
 */
export function isSetAside(state: LicenceModule['state']): boolean {
  return state === 'Failed' || state === 'Unresponsive' || state === 'Quarantined';
}

/**
 * A loaded module has a licence on disk it has not judged yet: a file just
 * uploaded or dropped into the folder. The module picks it up within a tick, so
 * the status is worth reading again soon.
 */
export function isBeingChecked(r: LicenceStatusResponse | undefined): boolean {
  return r?.module.state === 'Loaded' && r.licence.status === 'StoredNotVerified';
}

/**
 * A date as yyyy-mm-dd in UTC, or null when there is none. It reads the date the
 * server sent and does no arithmetic. Slicing the string instead would be wrong
 * for an offset other than UTC.
 */
export function isoDate(value: string | null | undefined): string | null {
  if (!value) return null;
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? null : date.toISOString().slice(0, 10);
}

/**
 * The server's day count as words. The module rounds down to whole days, so 0
 * means less than a day is left.
 */
export function daysPhrase(days: number | null | undefined): string | null {
  if (days === null || days === undefined) return null;
  if (days <= 0) return 'in less than a day';
  return days === 1 ? 'in 1 day' : `in ${days} days`;
}

/** A tier as the licence names it ("standard"), as a reader expects it ("Standard"). */
export function tierName(tier: string | null | undefined): string {
  if (!tier) return 'Unknown tier';
  return tier.charAt(0).toUpperCase() + tier.slice(1);
}

/** The CA limit as part of a sentence, or null when the licence carries none. */
export function casPhrase(maxCas: number | null | undefined): string | null {
  if (maxCas === null || maxCas === undefined) return null;
  if (maxCas >= NO_CA_LIMIT) return 'with no limit on CAs';
  return maxCas === 1 ? 'up to 1 CA' : `up to ${maxCas} CAs`;
}

/** A list of forest names as words: "a", "a and b", "a, b and c". */
export function forestList(forests: readonly string[]): string {
  if (forests.length === 0) return 'no forest';
  if (forests.length === 1) return forests[0];
  return `${forests.slice(0, -1).join(', ')} and ${forests[forests.length - 1]}`;
}

/**
 * Plain words for why the paid module refused a licence file, keyed by the
 * closed set of reason codes in design section 8.3. A code this page does not
 * know is still shown, so nothing is hidden behind a vague message.
 */
export function reasonWords(code: string | null | undefined): string {
  switch (code) {
    case 'TooLarge':
      return 'the file is too large to be a licence file';
    case 'MalformedEnvelope':
      return 'it is not a licence file, or its text was changed. If you pasted it, a mail program may have wrapped a long line; choose the file instead';
    case 'BadEncoding':
      return 'part of it is damaged. If you pasted it, a mail program may have wrapped a long line; choose the file instead';
    case 'UnsupportedHeader':
      return 'it is not a Ducks in a Row licence file';
    case 'UnknownKey':
      return 'it was signed with a key this paid module does not know. It may be a test licence, or the paid module may need updating';
    case 'BadSignature':
      return 'its signature does not match, so it was changed after it was issued';
    case 'MalformedClaims':
      return 'the licence details inside it cannot be read';
    case 'UnsupportedClaims':
      return 'it holds details this paid module does not understand. Update the paid module';
    case 'UnsupportedVersion':
      return 'it is in a newer format than this paid module reads. Update the paid module';
    case 'Revoked':
      return 'this licence has been withdrawn. Contact Haruspex Systems';
    case 'OutOfBounds':
      return 'a value in it is outside what a licence may hold';
    case null:
    case undefined:
    case '':
    case 'None':
      return 'the paid module could not read it';
    default:
      return `the paid module refused it (reason ${code})`;
  }
}

/** What the card shows: its tone, the main sentences, extra notes, and the host's own reason. */
export interface LicenceDescription {
  tone: LicenceTone;
  lines: string[];
  notes: string[];
  /** The module host's own words for a module that is not loaded, shown small. */
  detail: string | null;
  /** Retry is offered (and the server accepts it). */
  canRetry: boolean;
}

const UNTRUSTED_FOLDER =
  'The licence folder cannot be trusted, so no licence in it is read and paid features are off. ' +
  'An administrator must delete the folder named in the service log; the service then recreates it.';

const STORED_UNTIL_MODULE_RUNS = 'Your licence is stored, and is checked once the paid module runs.';

/**
 * Retry is not offered for Incompatible or Refused, because a restart alone
 * changes neither. But the paid module is looked for only when the service
 * starts, so once the fix is made a restart is exactly what is needed.
 */
const RESTART_AFTER_FIX =
  'The paid module is looked for only when the service starts, so restart the service (Restart-Service DucksInARow) once that is done.';

/** The card's text for one status response (design section 13.3). */
export function describeLicence(r: LicenceStatusResponse): LicenceDescription {
  const { module: m, stored, licence: l } = r;

  if (stored.untrusted) {
    return negative('red', [UNTRUSTED_FOLDER], [], null, false);
  }

  if (m.state !== 'Loaded') {
    return describeModule(r);
  }

  const notes = licenceNotes(l);

  switch (l.status) {
    case 'None': {
      const lines = ['The paid module is installed. Upload your licence file to switch on paid features.'];
      if (l.observedForest) lines.push(`This server is in ${l.observedForest}.`);
      return { tone: 'neutral', lines, notes, detail: null, canRetry: false };
    }
    case 'StoredNotVerified':
      return {
        tone: 'neutral',
        lines: ['A licence is stored and the paid module is checking it. This page updates when it has.'],
        notes,
        detail: null,
        canRetry: false,
      };
    case 'NotYetValid':
      return negative('amber',
        [`Your licence starts on ${dateOr(l.validFrom)}. Paid features are off until then.`], notes, null, false);
    case 'Valid': {
      const ref = l.licenseeRef ? ` (${l.licenseeRef})` : '';
      const cas = casPhrase(l.maxCas);
      return {
        tone: 'good',
        lines: [
          `Licensed to ${l.licenseeName ?? 'an unnamed licensee'}${ref}. ` +
            `${tierName(l.tier)}${cas ? `, ${cas}` : ''}. Valid until ${dateOr(l.validUntil)}.`,
        ],
        notes,
        detail: null,
        canRetry: false,
      };
    }
    case 'Expiring': {
      const days = daysPhrase(l.daysRemaining);
      return negative('amber', [
        `Your licence expires on ${dateOr(l.validUntil)}${days ? `, ${days}` : ''}. ` +
          'Upload the renewed file when it arrives.',
      ], notes, null, false);
    }
    case 'Grace':
      return negative('red', [
        `Your licence expired on ${dateOr(l.validUntil)}. Paid features switch off on ${dateOr(l.graceUntil)}.`,
      ], notes, null, false);
    case 'Lapsed':
      return negative('grey',
        [`Your licence lapsed on ${dateOr(l.graceUntil)}. Paid features are off.`], notes, null, false);
    case 'BindingMismatch':
      return negative('red', [bindingSentence(l)], notes, null, false);
    case 'Invalid':
      return negative('red',
        [`This licence file cannot be used: ${reasonWords(l.reasonCode)}.`], notes, null, false);
    default:
      return negative('red',
        [`The paid module reported a licence state this page does not recognise (${l.status}).`], notes, null, false);
  }
}

/**
 * The notes a verified licence carries beside its status: a server clock that
 * looks wrong (design section 9.2), and a tier the paid module does not know
 * (section 11.1). Shared by the card and the preview, so a file shows the same
 * warning before it is installed as after.
 */
export function licenceNotes(l: LicenceDetails): string[] {
  const notes: string[] = [];
  if (l.isVerified && l.clockAnomaly) {
    notes.push(
      "This server's clock looks wrong: it is more than a day behind the date this licence was issued. Correct the clock.");
  }
  if (l.isVerified && l.unknownTier) {
    notes.push(
      `This paid module does not know the ${tierName(l.tier)} tier, so it switches on no paid features for it. Update the paid module.`);
  }
  return notes;
}

/** The card's text for a module that is not loaded, whatever the licence (design section 13.3). */
function describeModule(r: LicenceStatusResponse): LicenceDescription {
  const { module: m, stored, licence: l } = r;
  const notes = stored.active ? [STORED_UNTIL_MODULE_RUNS] : [];

  switch (m.state) {
    case 'NotPresent':
      if (l.status === 'StoredNotVerified') {
        return negative('amber', [
          'A licence is stored but not checked, because the paid module is not installed. Install it to activate the licence.',
        ], [], null, false);
      }
      return { tone: 'neutral', lines: ['Free tier. No paid module is installed.'], notes: [], detail: null, canRetry: false };
    case 'Failed':
      return negative('red', ['The paid module failed to start or stopped with an error.'], notes, m.reason, true);
    case 'Unresponsive':
      return negative('red',
        ['The paid module stopped responding, so it gets no more calls until the service restarts.'], notes, m.reason, true);
    case 'Quarantined':
      return negative('red', ['The paid module was set aside after failing to start twice.'], notes, m.reason, true);
    case 'Incompatible': {
      const name = m.version ? `The paid module ${m.version}` : 'The paid module';
      const line = m.contract
        ? `${name} was built for contract ${m.contract.module}. This release needs a module built for contract ${m.contract.core}.`
        : `${name} was built for a different contract than this release needs.`;
      return negative('red', [line], [...notes, RESTART_AFTER_FIX], m.reason, false);
    }
    case 'Refused':
      return negative('red', [
        'The paid module was not loaded, because non-administrators can change its folder. Repair the module installation.',
      ], [...notes, RESTART_AFTER_FIX], m.reason, false);
    default:
      return negative('red',
        [`The paid module is in a state this page does not recognise (${m.state}).`], notes, m.reason, false);
  }
}

function negative(
  tone: LicenceTone,
  lines: string[],
  notes: string[],
  detail: string | null,
  canRetry: boolean,
): LicenceDescription {
  return { tone, lines: [...lines, NOT_AFFECTED], notes, detail, canRetry };
}

/**
 * BindingMismatch covers two module verdicts: bound to other forests, and bound
 * on a server that is not domain joined, which the module reports by its reason
 * code and by having no forest to name (design section 10.4).
 */
function bindingSentence(l: LicenceDetails): string {
  const forests = forestList(l.boundForests);
  if (l.reasonCode === 'NotDomainJoined' || !l.observedForest) {
    return `This licence is for ${forests}. This server is not joined to a domain, so it is in no forest. Paid features are off.`;
  }
  return `This licence is for ${forests}. This server is in ${l.observedForest}. Paid features are off.`;
}

function dateOr(value: string | null | undefined): string {
  return isoDate(value) ?? 'an unknown date';
}

/** The dashboard wide banner, or null when there is nothing to say. */
export interface LicenceBanner {
  tone: 'amber' | 'red' | 'grey';
  text: string;
  /** Only the grey Lapsed banner can be put away, and only for the browser session (design section 13.5). */
  dismissible: boolean;
  /** Identifies what the banner says, so a dismissal does not hide a later, different lapse. */
  key: string;
}

/**
 * The banner (design section 13.5, widened by Sean's decision of 2026-10-12): it
 * speaks only when a licence is stored, or the licence folder is refused, so a
 * free installation never sees one. Expiring is amber, Grace red and Lapsed grey,
 * and any other state that leaves a stored licence switching nothing on is
 * amber when it is a step not taken yet and red when something is broken.
 */
export function bannerFor(r: LicenceStatusResponse | undefined): LicenceBanner | null {
  if (!r) return null;
  const { module: m, stored, licence: l } = r;
  const key = `${m.state}|${l.status}|${l.licenceId ?? ''}|${l.graceUntil ?? ''}`;
  const make = (tone: LicenceBanner['tone'], text: string): LicenceBanner => ({
    tone,
    text: `${text} ${NOT_AFFECTED}`,
    dismissible: tone === 'grey',
    key,
  });

  if (stored.untrusted) return make('red', 'The licence folder cannot be trusted, so paid features are off.');
  if (!stored.active) return null;

  switch (m.state) {
    case 'Loaded':
      break;
    case 'NotPresent':
      return make('amber', 'A licence is stored, but the paid module is not installed, so paid features are off.');
    case 'Failed':
      return make('red', 'The paid module failed, so paid features are off.');
    case 'Unresponsive':
      return make('red', 'The paid module stopped responding, so paid features are off.');
    case 'Quarantined':
      return make('red', 'The paid module was set aside after failing to start twice, so paid features are off.');
    case 'Incompatible':
      return make('red', 'The paid module was built for another release, so paid features are off.');
    case 'Refused':
      return make('red', 'The paid module was not loaded because its folder is not protected, so paid features are off.');
    default:
      return make('red', 'The paid module is not running, so paid features are off.');
  }

  switch (l.status) {
    case 'Valid':
    case 'None':
    case 'StoredNotVerified':
      return null;
    case 'Expiring': {
      const days = daysPhrase(l.daysRemaining);
      return make('amber', `Your licence expires on ${dateOr(l.validUntil)}${days ? `, ${days}` : ''}.`);
    }
    case 'Grace':
      return make('red',
        `Your licence expired on ${dateOr(l.validUntil)}. Paid features switch off on ${dateOr(l.graceUntil)}.`);
    case 'Lapsed':
      return make('grey', `Your licence lapsed on ${dateOr(l.graceUntil)}. Paid features are off.`);
    case 'NotYetValid':
      return make('amber', `Your licence starts on ${dateOr(l.validFrom)}. Paid features are off until then.`);
    case 'BindingMismatch':
      return l.reasonCode === 'NotDomainJoined' || !l.observedForest
        ? make('red', 'The licence needs a server in its forest, and this one is not joined to a domain, so paid features are off.')
        : make('red', 'The licence is for another forest, so paid features are off.');
    case 'Invalid':
      return make('red', 'The licence file cannot be used, so paid features are off.');
    default:
      return make('red', 'The licence is in a state this page does not recognise, so paid features may be off.');
  }
}

/** The About block's Licence value (design section 13.1): the live tier. */
export function aboutTier(r: LicenceStatusResponse | undefined): string | null {
  if (!r) return null;
  const { module: m, stored, licence: l } = r;

  if (stored.untrusted) return 'Free tier (licence folder cannot be trusted)';
  if (!stored.active) return 'Free tier';
  if (m.state === 'NotPresent') return 'Free tier (paid module not installed)';
  if (m.state !== 'Loaded') return 'Free tier (paid module not running)';

  switch (l.status) {
    case 'Valid':
      return l.unknownTier ? `${tierName(l.tier)} (tier not known to this paid module)` : tierName(l.tier);
    case 'Expiring':
      return `${tierName(l.tier)}, expires ${dateOr(l.validUntil)}`;
    case 'Grace':
      return `${tierName(l.tier)}, paid features end ${dateOr(l.graceUntil)}`;
    case 'NotYetValid':
      return `Free tier until ${dateOr(l.validFrom)}`;
    case 'Lapsed':
      return `Free tier (licence lapsed ${dateOr(l.graceUntil)})`;
    case 'BindingMismatch':
      return 'Free tier (licence is for another forest)';
    case 'Invalid':
      return 'Free tier (licence file cannot be used)';
    case 'StoredNotVerified':
      return 'Free tier (licence not checked yet)';
    default:
      return 'Free tier';
  }
}

/** One labelled value of a licence, for the card, the preview and the downgrade comparison. */
export interface LicenceFact {
  label: string;
  value: string;
}

/**
 * The facts of a verified licence, or none for one that did not pass the
 * signature: nothing an unverified file says is ever shown (design section 8.4).
 * This server's forest is read off the server, so it is shown either way.
 */
export function licenceFacts(l: LicenceDetails): LicenceFact[] {
  const forest: LicenceFact = {
    label: "This server's forest",
    value: l.observedForest ?? 'Not joined to a domain',
  };
  if (!l.isVerified) return [forest];

  const facts: LicenceFact[] = [];
  if (l.licenseeName) facts.push({ label: 'Licensed to', value: l.licenseeName });
  if (l.licenseeRef) facts.push({ label: 'Reference', value: l.licenseeRef });
  facts.push({ label: 'Tier', value: tierName(l.tier) });
  if (l.maxCas !== null) {
    facts.push({ label: 'Connected CAs', value: l.maxCas >= NO_CA_LIMIT ? 'No limit' : `Up to ${l.maxCas}` });
  }
  const from = isoDate(l.validFrom);
  if (from) facts.push({ label: 'Valid from', value: from });
  const until = isoDate(l.validUntil);
  if (until) facts.push({ label: 'Valid until', value: until });
  const graceEnd = isoDate(l.graceUntil);
  if (graceEnd && graceEnd !== until) facts.push({ label: 'Paid features end', value: graceEnd });
  facts.push({ label: 'Bound to', value: l.boundForests.length ? forestList(l.boundForests) : 'Any forest' });
  facts.push(forest);
  if (l.licenceId) facts.push({ label: 'Licence id', value: l.licenceId });
  return facts;
}

/** How the preview of a candidate file reads, and what it offers. */
export type CandidateVerdict =
  | { kind: 'verified'; summary: string; worse: boolean; notes: string[] }
  | { kind: 'invalid'; summary: string }
  | { kind: 'unjudged'; summary: string }
  | { kind: 'noModule'; summary: string };

/**
 * The preview of a candidate file (design section 13.4, step 2). An Invalid
 * candidate offers no Activate (Sean's decision of 2026-10-12): stored, it could
 * never switch anything on. A loaded module that could not judge the file offers
 * none either, because the install would answer 503. With no module to judge
 * it, the file can still be stored, so the order the module and the licence
 * arrive in does not matter.
 */
export function describeCandidate(inspect: LicenceInspectResponse): CandidateVerdict {
  const c = inspect.candidate;
  if (!c) {
    return inspect.module.state === 'Loaded'
      ? { kind: 'unjudged', summary: 'The paid module could not check this file. Try again; if it keeps failing, the service log says why.' }
      : { kind: 'noModule', summary: 'This file cannot be checked now, because the paid module is not running. It can be stored, and is checked once the paid module runs.' };
  }

  const l = c.licence;
  if (l.status === 'Invalid' || !l.isVerified) {
    return { kind: 'invalid', summary: `This licence file cannot be used: ${reasonWords(l.reasonCode)}.` };
  }

  let summary: string;
  switch (l.status) {
    case 'Valid':
      summary = `This licence is valid until ${dateOr(l.validUntil)}.`;
      break;
    case 'Expiring': {
      const days = daysPhrase(l.daysRemaining);
      summary = `This licence is valid, and expires on ${dateOr(l.validUntil)}${days ? `, ${days}` : ''}.`;
      break;
    }
    case 'Grace':
      summary = `This licence expired on ${dateOr(l.validUntil)}. Paid features would stay on until ${dateOr(l.graceUntil)}.`;
      break;
    case 'Lapsed':
      summary = `This licence lapsed on ${dateOr(l.graceUntil)}, so it would switch no paid features on.`;
      break;
    case 'NotYetValid':
      summary = `This licence starts on ${dateOr(l.validFrom)}. Until then it switches no paid features on.`;
      break;
    case 'BindingMismatch':
      summary = `${bindingSentence(l).replace('Paid features are off.', 'It would switch no paid features on here.')}`;
      break;
    default:
      summary = `The paid module reported a licence state this page does not recognise (${l.status}).`;
  }
  return { kind: 'verified', summary, worse: c.worseThanInstalled, notes: licenceNotes(l) };
}
