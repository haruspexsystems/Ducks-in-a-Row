import { useQuery } from '@tanstack/react-query';
import { fetchLicence } from '@/api/licence';
import { isBeingChecked } from '@/lib/licence';

/**
 * The one query key for the licence status, shared by the Settings card, the
 * dashboard wide banner and the About block, so the three never disagree and
 * the endpoint is read once (issue #493). A change on the card writes its own
 * response into this key.
 */
export const licenceKey = ['settings', 'licence'] as const;

/** Every hour: the module evaluates the licence again at least hourly, so stages advance (design section 12.5). */
const HOURLY = 60 * 60 * 1000;

/** While a loaded module has not judged a stored file yet, which takes it one tick. */
const WHILE_CHECKING = 5_000;

/**
 * The longest the fast poll runs. A file the module should judge within a 30
 * second tick and still has not after this is not going to be judged by asking
 * faster, and every open tab polls, since the banner is on every page.
 */
const CHECKING_AT_MOST = 2 * 60 * 1000;

let checkingSince: number | null = null;

function interval(checking: boolean): number {
  if (!checking) {
    checkingSince = null;
    return HOURLY;
  }
  checkingSince ??= Date.now();
  return Date.now() - checkingSince < CHECKING_AT_MOST ? WHILE_CHECKING : HOURLY;
}

/**
 * The licence status. It is read again every hour, because the browser never
 * counts days itself: a dashboard left open for days must ask the server what
 * the day count is now, rather than show the one it read when it opened.
 */
export function useLicence() {
  return useQuery({
    queryKey: licenceKey,
    queryFn: fetchLicence,
    staleTime: 60_000,
    retry: false,
    refetchOnWindowFocus: false,
    refetchInterval: (query) => interval(isBeingChecked(query.state.data)),
  });
}
