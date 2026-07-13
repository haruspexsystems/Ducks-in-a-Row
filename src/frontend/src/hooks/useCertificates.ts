import { useQuery, keepPreviousData } from '@tanstack/react-query';
import {
  fetchCertificates,
  fetchCertificate,
  fetchStats,
  fetchTemplates,
} from '@/api/client';
import type { CertificateQuery } from '@/types';

/** Fetch paginated certificate list with React Query. */
export function useCertificates(query: CertificateQuery = {}) {
  return useQuery({
    queryKey: ['certificates', query],
    queryFn: () => fetchCertificates(query),
    placeholderData: keepPreviousData,
    staleTime: 30_000, // 30 seconds
  });
}

/** Fetch a single certificate by ID. */
export function useCertificate(id: number) {
  return useQuery({
    queryKey: ['certificate', id],
    queryFn: () => fetchCertificate(id),
    enabled: id > 0,
  });
}

/** Fetch dashboard summary stats. */
export function useStats() {
  return useQuery({
    queryKey: ['stats'],
    queryFn: fetchStats,
    staleTime: 60_000, // 1 minute
    refetchInterval: 60_000,
  });
}

/** Fetch available templates. */
export function useTemplates() {
  return useQuery({
    queryKey: ['templates'],
    queryFn: fetchTemplates,
    staleTime: 300_000, // 5 minutes
  });
}
