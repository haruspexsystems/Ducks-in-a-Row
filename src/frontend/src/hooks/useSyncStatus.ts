import { useCallback, useState } from 'react';
import { useQuery, useQueryClient } from '@tanstack/react-query';
import { fetchSyncStatus, triggerSync } from '@/api/client';

/** Query key for the sync status, invalidated after every manual sync. */
export const syncStatusKey = ['sync-status'] as const;

/**
 * The connected CA and last sync outcome for the page headers (issue #157).
 * Polls at the dashboard's 60 second cadence so a background sync, or a
 * background failure, surfaces without a reload. Consumers must treat
 * undefined data as "status unknown" and keep rendering; this query failing
 * must never blank a page.
 */
export function useSyncStatus() {
  return useQuery({
    queryKey: syncStatusKey,
    queryFn: fetchSyncStatus,
    staleTime: 30_000,
    // refetchIntervalInBackground defaults to false, so hidden tabs do not poll.
    refetchInterval: 60_000,
  });
}

/**
 * Shared Refresh button behavior for the certificate list and the dashboard:
 * pull the inventory from the CA, surface a failure as a dismissible notice
 * instead of swallowing it (issue #157), then always run the caller's refetch,
 * because a sync failure must not block refetching what is already local.
 * The sync status query is refreshed either way, so the header indicator
 * follows the outcome.
 */
export function useManualSync(onSettled?: () => void) {
  const queryClient = useQueryClient();
  const [syncing, setSyncing] = useState(false);
  const [syncError, setSyncError] = useState<unknown>(null);

  const runSync = useCallback(async () => {
    setSyncing(true);
    setSyncError(null);
    try {
      await triggerSync();
    } catch (error) {
      setSyncError(error);
    } finally {
      setSyncing(false);
    }
    queryClient.invalidateQueries({ queryKey: syncStatusKey });
    onSettled?.();
  }, [queryClient, onSettled]);

  const dismissSyncError = useCallback(() => setSyncError(null), []);

  return { syncing, syncError, runSync, dismissSyncError };
}
