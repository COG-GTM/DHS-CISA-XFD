import {
  Dialog,
  DialogContent,
  DialogTitle,
  IconButton,
  Paper
} from '@mui/material';
import OpenInNewIcon from '@mui/icons-material/OpenInNew';
import { Box } from '@mui/system';
import {
  DataGrid,
  GridColDef,
  GridFilterItem,
  GridRenderEditCellParams
} from '@mui/x-data-grid';
import { useAuthContext } from 'context';
import { format, parseISO } from 'date-fns';
import React, { FC, useCallback, useEffect, useState } from 'react';
import CustomToolbar from 'components/DataGrid/CustomToolbar';

interface LogsProps {}

interface LogDetails {
  created_at: string;
  event_type: string;
  result: string;
  // payload: string;
  payload: {
    user?: {
      email: string;
    };
    user_performed_assignment: {
      email: string;
      [key: string]: any;
    };
  };
}

const PAGE_SIZE = 15;

export const Logs: FC<LogsProps> = () => {
  const { apiPost } = useAuthContext();
  const [filters, setFilters] = useState<Array<GridFilterItem>>([]);
  const [openDialog, setOpenDialog] = useState(false);
  const [dialogDetails, setDialogDetails] = useState<
    (LogDetails & { id: number }) | null
  >(null);
  const [logs, setLogs] = useState<{
    count: Number;
    result: Array<LogDetails>;
  }>({
    count: 0,
    result: []
  });

  const fetchLogs = useCallback(async () => {
    const tableFilters = filters.reduce(
      (acc: { [key: string]: { value: any; operator: any } }, cur) => {
        return {
          ...acc,
          [cur.field]: {
            value: cur.value,
            operator: cur.operator
          }
        };
      },
      {}
    );
    const endpoint =
      Object.keys(tableFilters).length > 0
        ? '/logs/filtered-search'
        : '/logs/search';
    try {
      const body =
        endpoint === '/logs/filtered-search'
          ? {
              page: 1,
              page_size: PAGE_SIZE,
              filters: tableFilters
            }
          : {};
      const results = await apiPost(endpoint, { body });
      console.log(`API response from ${endpoint}:`, results);
      if (
        !results ||
        !Array.isArray(results.result) ||
        typeof results.count !== 'number'
      ) {
        console.error('Invalid response format:', results);
        setLogs({ count: 0, result: [] });
        return;
      }
      setLogs(results);
    } catch (e) {
      console.error(`Fetch logs error from ${endpoint}:`, e);
      setLogs({ count: 0, result: [] });
    }
  }, [apiPost, filters]);

  useEffect(() => {
    fetchLogs();
  }, [fetchLogs]);

  const logCols: GridColDef[] = [
    {
      field: 'event_type',
      headerName: 'Event',
      minWidth: 100,
      flex: 1.25
    },
    {
      field: 'payload.user.email',
      headerName: 'User Assigned',
      minWidth: 100,
      flex: 1.5,
      valueGetter: (params) => params.row.payload?.user?.email || 'N/A'
    },
    {
      field: 'payload.user_performed_assignment.email',
      headerName: 'Assigned By',
      minWidth: 100,
      flex: 1.5,
      valueGetter: (params) =>
        params.row.payload?.user_performed_assignment?.email || 'N/A'
    },
    {
      field: 'result',
      headerName: 'Result',
      minWidth: 100,
      flex: 1
    },
    {
      field: 'created_at',
      headerName: 'Timestamp',
      type: 'dateTime',
      minWidth: 100,
      flex: 1.5,
      valueFormatter: (e) => {
        return format(parseISO(e.value), 'MM/dd/yyyy hh:mm a');
      }
    },
    {
      field: 'payload',
      headerName: 'Payload',
      description: 'Click any payload cell to expand.',
      sortable: false,
      minWidth: 300,
      flex: 2,
      renderCell: (cellValues) => {
        return (
          <Box
            sx={{
              fontSize: '12px',
              padding: 0,
              margin: 0,
              backgroundColor: 'black',
              color: 'white',
              width: '100%'
            }}
          >
            <pre>{JSON.stringify(cellValues.row.payload, null, 2)}</pre>
          </Box>
        );
      },
      valueFormatter: (e) => {
        return JSON.stringify(e.value, null, 2);
      }
    },
    {
      field: 'details',
      headerName: 'Details',
      maxWidth: 70,
      flex: 1,
      renderCell: (cellValues: GridRenderEditCellParams) => {
        return (
          <IconButton
            aria-label={`Details for scan task ${cellValues.row.id}`}
            tabIndex={cellValues.tabIndex}
            color="primary"
            onClick={() => {
              setOpenDialog(true);
              setDialogDetails(cellValues.row);
            }}
          >
            <OpenInNewIcon />
          </IconButton>
        );
      }
    }
  ];

  useEffect(() => {
    fetchLogs();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filters]);

  return (
    <Box display="flex">
      <Paper elevation={2} sx={{ width: '100%', minHeight: '200px' }}>
        <DataGrid
          rows={logs.result}
          columns={logCols}
          filterMode="server"
          slots={{
            toolbar: CustomToolbar
          }}
          slotProps={{ toolbar: { multifilter: true } }}
          onFilterModelChange={(model) => {
            setFilters(model.items);
          }}
          initialState={{
            pagination: { paginationModel: { pageSize: 15 } },
            sorting: {
              sortModel: [{ field: 'created_at', sort: 'desc' }]
            }
          }}
          pageSizeOptions={[15, 30, 50, 100]}
        />
      </Paper>
      <Dialog
        open={openDialog}
        onClose={() => setOpenDialog(false)}
        scroll="paper"
        fullWidth
        maxWidth="lg"
      >
        <DialogTitle>Payload Details</DialogTitle>
        <DialogContent>
          <Box
            sx={{
              fontSize: '12px',
              padding: 2,
              margin: 0,
              backgroundColor: 'black',
              color: 'white',
              width: '100%'
            }}
          >
            <pre>{JSON.stringify(dialogDetails?.payload, null, 2)}</pre>
          </Box>
        </DialogContent>
      </Dialog>
    </Box>
  );
};
