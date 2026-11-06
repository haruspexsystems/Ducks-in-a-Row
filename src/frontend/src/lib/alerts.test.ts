import { describe, it, expect } from 'vitest';
import type { AlertConfig, AlertSmtpConfig, AlertWebhookConfig } from '@/api/alerts';
import { alertsAttention, describeChannelOutcome } from './alerts';

function config(
  enabled: boolean,
  smtp: Partial<AlertSmtpConfig> | null,
  webhook: Partial<AlertWebhookConfig> | null,
): AlertConfig {
  // Only the fields the rule reads matter; the rest are filler.
  return {
    enabled,
    checkIntervalMinutes: 60,
    thresholdDays: [30, 14, 7, 1],
    expiryWarningDays: 30,
    smtp: smtp as AlertSmtpConfig | null,
    webhook: webhook as AlertWebhookConfig | null,
  } as AlertConfig;
}

/**
 * When the dashboard warns that nothing will be alerted (issue #471). In monitor
 * mode alerts are the product, and with no channel the expiry monitor skips its
 * pass with nothing but a Debug line to show for it.
 */
describe('alertsAttention', () => {
  it('flags alerting that is switched off', () => {
    expect(alertsAttention(config(false, { enabled: true }, null))).toBe('disabled');
  });

  it('flags alerting with neither channel able to deliver', () => {
    expect(alertsAttention(config(true, null, null))).toBe('noChannel');
    expect(alertsAttention(config(true, { enabled: false }, { enabled: false }))).toBe('noChannel');
  });

  it('is satisfied by email alone or a webhook alone', () => {
    expect(alertsAttention(config(true, { enabled: true }, null))).toBeNull();
    expect(alertsAttention(config(true, null, { enabled: true }))).toBeNull();
  });

  it('says nothing before the configuration has loaded', () => {
    expect(alertsAttention(undefined)).toBeNull();
    expect(alertsAttention(null)).toBeNull();
  });
});

/**
 * What the alert history says about each channel (issue #206). The point of the
 * column is that a partial failure must not read as total, and a row from before
 * the column must not claim to know which channel failed.
 */
describe('describeChannelOutcome', () => {
  it('names the channel that delivered beside the one that failed', () => {
    const outcome = describeChannelOutcome({
      channels: 'email,webhook',
      deliveredChannels: 'email',
      success: false,
    });

    expect(outcome.verb).toBe('Sent');
    expect(outcome.partial).toBe(true);
    expect(outcome.channels).toBe('Delivered over email. Failed over webhook.');
    expect(outcome.failure).toBe(
      'Ducks does not retry a threshold it has already recorded, so this warning will not be sent again over webhook.',
    );
  });

  it('reads as failed only when no channel delivered', () => {
    const outcome = describeChannelOutcome({
      channels: 'email,webhook',
      deliveredChannels: '',
      success: false,
    });

    expect(outcome.verb).toBe('Failed');
    expect(outcome.partial).toBe(false);
    expect(outcome.channels).toBe('Failed over email, webhook.');
    expect(outcome.failure).toBe(
      'Ducks does not retry a threshold it has already recorded, so this warning will not be sent again.',
    );
  });

  it('says every channel delivered and has no failure to explain', () => {
    const outcome = describeChannelOutcome({
      channels: 'email,webhook',
      deliveredChannels: 'email,webhook',
      success: true,
    });

    expect(outcome.verb).toBe('Sent');
    expect(outcome.channels).toBe('Delivered over email, webhook.');
    expect(outcome.failure).toBeNull();
  });

  it('keeps the old wording for a failed row that predates the column', () => {
    const outcome = describeChannelOutcome({ channels: 'email,webhook', success: false });

    expect(outcome.verb).toBe('Failed');
    expect(outcome.partial).toBe(false);
    expect(outcome.channels).toBe('Attempted over email, webhook.');
    expect(outcome.failure).toMatch(/^At least one channel failed\./);
    expect(outcome.channels).not.toMatch(/Delivered/);
  });
});