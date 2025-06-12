import React, { useCallback, useState, useEffect, useMemo } from 'react';
import { useHistory, useLocation } from 'react-router-dom';
import { Query } from 'types';
import { Domain } from 'types';
import { useAuthContext } from 'context';
import { useDomainApi } from 'hooks';
import { Box, Stack } from '@mui/system';
import {
  Alert,
  Button,
  Divider,
  IconButton,
  Paper,
  Typography
} from '@mui/material';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import FiberManualRecordRounded from '@mui/icons-material/FiberManualRecordRounded';
import { DataGrid, GridColDef, GridRenderCellParams } from '@mui/x-data-grid';
import CustomToolbar from 'components/DataGrid/CustomToolbar';
import CustomNoRowsOverlay from 'components/DataGrid/CustomNoRowsOverlay';
import { differenceInCalendarDays, parseISO } from 'date-fns';
import { FindingsHeader } from 'components/FindingsLibrary/FindingsHeader';
import { extractInitialFilters } from 'utils/vulnerabilitiesTableUtils';

const PAGE_SIZE = 15;

export interface DomainRow {
  id: string;
  organization_name: string;
  name: string;
  ip: string;
  ports: string[];
  service: string[];
  vulnerabilities: (string | null)[];
  updated_at: string;
  created_at: string;
}

export const Domains: React.FC = () => {
  const location = useLocation();
  const state = location.state as
    | { orgName?: string; orgId?: string }
    | undefined;
  const { showAllOrganizations } = useAuthContext();
  const [domains, setDomains] = useState<Domain[]>([]);
  const [totalResults, setTotalResults] = useState(0);
  const { listDomains } = useDomainApi(
    showAllOrganizations,
    state?.orgId ?? ''
  );
  const history = useHistory();
  const [initialFilters, setInitialFilters] = useState<
    Query<Domain>['filters']
  >(() => extractInitialFilters(state ?? {}));
  const filters = useMemo(() => {
    return initialFilters.length > 0 ? initialFilters : [];
  }, [initialFilters]);

  const [loadingError, setLoadingError] = useState(false);
  const [isLoading, setIsLoading] = useState(false);

  // TO-DO
  // Implement regional rollup on domains view to allow for proper domain drilldown from dashboard
  const fetchDomains = useCallback(
    async (q: Query<Domain>) => {
      try {
        const { domains, count } = await listDomains(q);
        if (domains.length === 0) {
          setDomains([]);
          setTotalResults(0);
          setPaginationModel((prevState) => ({
            ...prevState,
            page: 0,
            pageSize: PAGE_SIZE,
            pageCount: 0,
            filters: q.filters
          }));
          setLoadingError(false);
          return;
        }
        setDomains(domains);
        setTotalResults(count);
        setPaginationModel((prevState) => ({
          ...prevState,
          page: q.page - 1,
          pageSize: q.pageSize ?? PAGE_SIZE,
          pageCount: Math.ceil(count / (q.pageSize ?? PAGE_SIZE)),
          filters: q.filters
        }));
      } catch (e) {
        console.error(e);
        setLoadingError(true);
      } finally {
        setIsLoading(false);
      }
    },
    [listDomains]
  );

  const [paginationModel, setPaginationModel] = useState({
    page: 0,
    pageSize: PAGE_SIZE,
    pageCount: 0,
    filters: filters
  });

  useEffect(() => {
    setIsLoading(true);
    fetchDomains({
      page: 1,
      pageSize: PAGE_SIZE,
      filters: filters
    });
  }, [fetchDomains, filters]);

  const resetDomains = useCallback(() => {
    const clearedFilters: Query<Domain>['filters'] = [];

    setInitialFilters(clearedFilters);
    setPaginationModel({
      page: 0,
      pageSize: PAGE_SIZE,
      pageCount: 0,
      filters: clearedFilters
    });

    fetchDomains({
      page: 1,
      pageSize: PAGE_SIZE,
      filters: clearedFilters
    });
  }, [fetchDomains]);

  const domRows: DomainRow[] = domains.map((domain) => ({
    id: domain.id,
    organization_name: domain.organization.name,
    name: domain.name,
    ip: domain.ip,
    ports: [domain.services.map((service) => service.port).join(', ')],
    service: domain.services.map((service) =>
      service.products.map((p) => p.name).join(', ')
    ),
    vulnerabilities: domain.vulnerabilities.map((vuln) => vuln.title),
    updated_at: `${differenceInCalendarDays(
      Date.now(),
      parseISO(domain.updated_at)
    )} days ago`,
    created_at: `${differenceInCalendarDays(
      Date.now(),
      parseISO(domain.created_at)
    )} days ago`
  }));

  const domCols: GridColDef[] = [
    {
      field: 'organization_name',
      headerName: 'Organization',
      minWidth: 100,
      flex: 1.5
    },
    { field: 'name', headerName: 'Domain', minWidth: 100, flex: 1 },
    { field: 'ip', headerName: 'IP', minWidth: 50, flex: 1 },
    { field: 'ports', headerName: 'Ports', minWidth: 100, flex: 0.8 },
    { field: 'service', headerName: 'Services', minWidth: 100, flex: 1 },
    {
      field: 'vulnerabilities',
      headerName: 'Vulnerabilities',
      minWidth: 100,
      flex: 1.5
    },
    { field: 'updated_at', headerName: 'Updated At', minWidth: 50, flex: 0.9 },
    { field: 'created_at', headerName: 'Created At', minWidth: 50, flex: 0.9 },

    {
      field: 'view',
      headerName: 'Details',
      minWidth: 100,
      flex: 0.3,
      disableExport: true,
      renderCell: (cellValues: GridRenderCellParams) => {
        return (
          <IconButton
            aria-label={`View details for ${cellValues.row.name}`}
            tabIndex={cellValues.tabIndex}
            color="primary"
            onClick={() =>
              history.push('/inventory/domain/' + cellValues.row.id)
            }
          >
            <OpenInNewIcon />
          </IconButton>
        );
      }
    }
  ];

  const noRowsOverlay = (
    <Paper>
      <Alert severity="warning">
        No Results Found. Please adjust your filters.
      </Alert>
    </Paper>
  );

  return (
    <FindingsHeader>
      {!isLoading && !loadingError && state && filters.length > 0 && (
        <Box sx={{ width: '100%', mb: 1 }}>
          <Stack direction="row" alignItems="center">
            <FiberManualRecordRounded sx={{ color: 'primary.main' }} />
            <Typography variant="body1" color="neutrals.main">
              &nbsp;Filters Applied:
            </Typography>
            {state.orgName ? (
              <Typography variant="body1" color="neutrals.main" ml={1}>
                <b>Organization</b> - {state.orgName}
              </Typography>
            ) : (
              ''
            )}
            &nbsp;&nbsp;&nbsp;
            <Divider
              orientation="vertical"
              flexItem
              variant="middle"
              sx={{
                height: 24,
                alignSelf: 'center',
                borderColor: 'neutrals.light',
                ml: 2
              }}
            />
            <Button
              variant="text"
              onClick={resetDomains}
              sx={{
                color: 'primary.dark',
                fontSize: '14px',
                letterSpacing: '3px',
                ml: 2
              }}
            >
              Reset
            </Button>
          </Stack>
        </Box>
      )}
      <Box mb={3} display="flex" justifyContent="center">
        {isLoading ? (
          <Paper elevation={2}>
            <Alert severity="info">Loading Domains..</Alert>
          </Paper>
        ) : isLoading === false && loadingError === true ? (
          <Stack direction="row" spacing={2}>
            <Paper elevation={2}>
              <Alert severity="warning">Error Loading Domains!</Alert>
            </Paper>
            <Button
              onClick={() => fetchDomains}
              variant="contained"
              color="primary"
              sx={{ width: 'fit-content' }}
            >
              Retry
            </Button>
          </Stack>
        ) : isLoading === false && loadingError === false ? (
          <Paper elevation={2} sx={{ width: '100%', minHeight: 500 }}>
            <DataGrid
              rows={domRows}
              rowCount={totalResults}
              columns={domCols}
              slots={{
                toolbar: CustomToolbar,
                noRowsOverlay: CustomNoRowsOverlay
              }}
              slotProps={{
                noRowsOverlay: { children: noRowsOverlay },
                toolbar: { exportTitle: 'Domains' } as any
              }}
              paginationMode="server"
              paginationModel={paginationModel}
              onPaginationModelChange={(model) => {
                fetchDomains({
                  page: model.page + 1,
                  pageSize: model.pageSize,
                  filters: filters
                });
              }}
              onFilterModelChange={(model) => {
                const filters = model.items.map((item) => ({
                  id: item.field,
                  field: item.field,
                  value: item.value,
                  operator: item.operator
                }));
                setInitialFilters(filters);
                fetchDomains({
                  page: paginationModel.page + 1,
                  pageSize: paginationModel.pageSize,
                  filters: filters
                });
              }}
              pageSizeOptions={[15, 30, 50, 100]}
            />
          </Paper>
        ) : null}
      </Box>
    </FindingsHeader>
  );
};
