import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { ErrorBoundary } from '@/components/ErrorBoundary';
import { Layout } from '@/components/Layout';
import { RequireSetup } from '@/components/RequireSetup';
import { DashboardPage } from '@/pages/DashboardPage';
import { CertificateListPage } from '@/pages/CertificateListPage';
import { CertificateDetailPage } from '@/pages/CertificateDetailPage';
import { SettingsPage } from '@/pages/SettingsPage';
import { SetupWizard } from '@/pages/setup/SetupWizard';

const queryClient = new QueryClient({
  defaultOptions: {
    queries: {
      retry: 1,
      refetchOnWindowFocus: false,
    },
  },
});

export default function App() {
  return (
    <ErrorBoundary>
      <QueryClientProvider client={queryClient}>
        <BrowserRouter>
          <Routes>
            {/* Setup wizard — standalone layout (no nav bar) */}
            <Route path="/setup" element={<SetupWizard />} />

            {/* Main dashboard — with nav bar (gated on setup being complete) */}
            <Route element={<RequireSetup><Layout /></RequireSetup>}>
              <Route path="/" element={<DashboardPage />} />
              <Route path="/certificates" element={<CertificateListPage />} />
              <Route path="/certificates/:id" element={<CertificateDetailPage />} />
              <Route path="/settings" element={<SettingsPage />} />
            </Route>

            {/* Unknown paths fall back to the dashboard */}
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </BrowserRouter>
      </QueryClientProvider>
    </ErrorBoundary>
  );
}
