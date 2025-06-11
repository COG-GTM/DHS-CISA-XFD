import { Query, Domain, DomainSearchApiResponse } from 'types';
import { useAuthContext } from 'context';
import { useCallback } from 'react';
import { ORGANIZATION_EXCLUSIONS } from './useUserTypeFilters';

export interface DomainQuery extends Query<DomainSearchApiResponse> {
  showAll?: boolean;
}

interface ApiResponse {
  result: DomainSearchApiResponse[];
  count: number;
  url?: string;
}

const PAGE_SIZE = 15;

export const useDomainApi = (showAll?: boolean) => {
  const { currentOrganization, apiPost, apiGet } = useAuthContext();
  const listDomains = useCallback(
    async (query: DomainQuery, doExport = false) => {
      const { page, filters, page_size = PAGE_SIZE } = query;
      const tableFilters: any = filters
        .filter((f) => Boolean(f.value))
        .reduce(
          (accum, next) => ({
            ...accum,
            [next.field]: next.value
          }),
          {}
        );
      let userOrgIsExcluded = false;
      ORGANIZATION_EXCLUSIONS.forEach((exc) => {
        if (currentOrganization?.name.toLowerCase().includes(exc)) {
          userOrgIsExcluded = true;
        }
      });
      if (currentOrganization && !userOrgIsExcluded) {
        tableFilters['organization'] = currentOrganization.id;
      }

      const { result, count, url } = await apiPost<ApiResponse>(
        doExport ? '/domain/export' : '/domain/search',
        {
          body: {
            page_size,
            page,
            filters: tableFilters
          }
        }
      );

      return {
        domains: result,
        count,
        url,
        pageCount: Math.ceil(count / page_size)
      };
    },
    [apiPost, currentOrganization]
  );

  const getDomain = useCallback(
    async (domainId: string) => {
      return await apiGet<Domain>(`/domain/${domainId}`);
    },
    [apiGet]
  );

  return {
    listDomains,
    getDomain
  };
};
