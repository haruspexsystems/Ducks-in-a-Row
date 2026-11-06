import type { AlertConfig } from '@/api/alerts';

/**
 * Why alerting needs an administrator's attention, or null when it does not.
 * 'disabled' means the alert service is switched off; 'noChannel' means it is on
 * but neither email nor a webhook could deliver anything, which is when the
 * expiry monitor quietly skips its pass. A configuration that has not loaded is
 * null, so nothing warns before there is something to warn about.
 *
 * In monitor mode alerts are the product (issue #471), so the dashboard shows a
 * warning while this answers anything but null.
 */
export type AlertsAttention = 'disabled' | 'noChannel' | null;

export function alertsAttention(config: AlertConfig | null | undefined): AlertsAttention {
  if (!config) return null;
  if (!config.enabled) return 'disabled';
  if (!config.smtp?.enabled && !config.webhook?.enabled) return 'noChannel';
  return null;
}

/** What a recorded expiry alert says about its channels, as the history renders it. */
export interface ChannelOutcome {
  /** 'Sent' when any channel delivered, so a partial failure never reads as total. */
  verb: 'Sent' | 'Failed';
  /** True when a channel failed and another delivered. */
  partial: boolean;
  /** The sentence naming the channels. */
  channels: string;
  /** What the failure costs, or null when every channel delivered. */
  failure: string | null;
}

const NOT_RETRIED =
  'Ducks does not retry a threshold it has already recorded, so this warning will not be sent again';

function channelList(value: string | undefined): string[] {
  return (value ?? '').split(',').filter(Boolean);
}

/**
 * The channel sentences for one recorded alert (issue #206), shared by the
 * certificate's alert ladder and the fleet wide history.
 *
 * deliveredChannels is absent on a failed row written before the outcome was
 * kept per channel. Such a row cannot say which channel failed, so it keeps the
 * old wording: "attempted", and "at least one channel failed", never a claim
 * that nobody was told.
 */
export function describeChannelOutcome(row: {
  channels?: string;
  deliveredChannels?: string;
  success: boolean;
}): ChannelOutcome {
  const attempted = channelList(row.channels);

  if (row.deliveredChannels == null) {
    return {
      verb: row.success ? 'Sent' : 'Failed',
      partial: false,
      channels: `Attempted over ${attempted.join(', ')}.`,
      failure: row.success ? null : `At least one channel failed. ${NOT_RETRIED}.`,
    };
  }

  const delivered = channelList(row.deliveredChannels);
  const failed = attempted.filter((c) => !delivered.includes(c));
  const sentences = [
    delivered.length > 0 ? `Delivered over ${delivered.join(', ')}.` : null,
    failed.length > 0 ? `Failed over ${failed.join(', ')}.` : null,
  ].filter(Boolean);

  const partial = !row.success && delivered.length > 0;
  let failure: string | null = null;
  if (!row.success) {
    failure =
      partial && failed.length > 0
        ? `${NOT_RETRIED} over ${failed.join(', ')}.`
        : `${NOT_RETRIED}.`;
  }

  return {
    verb: delivered.length > 0 ? 'Sent' : 'Failed',
    partial,
    channels: sentences.join(' '),
    failure,
  };
}
