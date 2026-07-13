import type { ReactNode } from 'react';
import { Navigate } from 'react-router-dom';
import { useQuery } from '@tanstack/react-query';
import { Loader2 } from 'lucide-react';
import { fetchSetupStatus } from '@/api/setup';

/**
 * Gate for the main dashboard routes. On a fresh install setup is not complete,
 * so send the user to the wizard instead of a dashboard that can only show API
 * errors. If the status check itself fails we fail open and render the app, so a
 * flaky status endpoint never traps the user behind a redirect.
 */
export function RequireSetup({ children }: { children: ReactNode }) {
  const { data, isLoading, isError } = useQuery({
    queryKey: ['setup-status'],
    queryFn: fetchSetupStatus,
    staleTime: 5 * 60_000, // status rarely changes
  });

  if (isLoading) {
    return (
      <div className="min-h-screen bg-[#F6F7F9] flex items-center justify-center">
        <Loader2 className="h-8 w-8 text-certus-500 animate-spin" />
      </div>
    );
  }

  if (!isError && data && !data.setupCompleted) {
    return <Navigate to="/setup" replace />;
  }

  return <>{children}</>;
}
