import React from 'react';
import {
  Alert,
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableRow
} from '@mui/material';
import { SxProps } from '@mui/system';

type ColumnConfig<T> = {
  key: keyof T;
  header: string;
  textAlign?: 'left' | 'center' | 'right';
  minWidth?: number | string;
  render?: (value: T[keyof T], row: T) => React.ReactNode;
  headerPadding?: number;
};

type RoundedTableProps<T> = {
  columns: ColumnConfig<T>[];
  data: T[];
  noDataMessage?: string;
  tableStyles?: SxProps;
  rowHeadStyles?: SxProps;
  rowBodyStyles?: SxProps;
  cellBodyStyles?: SxProps;
};

const tableSx: SxProps = {
  borderCollapse: 'separate',
  borderSpacing: '0 16px',
  width: '100%',
  tableLayout: 'auto'
};

const rowHeadSx: SxProps = {
  '& th': {
    border: 'none',
    backgroundColor: 'transparent',
    pb: 0,
    fontSize: '11px',
    fontWeight: 600
  }
};

const rowBodySx = {
  borderRadius: 5,
  borderColor: 'gray',
  '& td': {
    borderLeft: '1px solid #ccc',
    backgroundColor: '#fff',
    py: '5px',
    px: 2
  },
  '& td:first-of-type': {
    borderTopLeftRadius: 8,
    borderBottomLeftRadius: 8
  },
  '& td:last-of-type': {
    borderTopRightRadius: 8,
    borderBottomRightRadius: 8
  }
};

const cellBodySx = {
  border: '1px solid',
  borderColor: 'neutrals.light',
  height: '64px'
};

export default function RoundedTable<T extends Record<string, any>>({
  columns,
  data,
  noDataMessage = 'No data available.',
  tableStyles = tableSx,
  rowHeadStyles = rowHeadSx,
  rowBodyStyles = rowBodySx,
  cellBodyStyles = cellBodySx
}: RoundedTableProps<T>) {
  if (data.length === 0) {
    return (
      <Alert severity="info" sx={{ width: '100%', mt: 2 }}>
        {noDataMessage}
      </Alert>
    );
  }

  return (
    <Table sx={tableStyles}>
      <TableHead>
        <TableRow sx={rowHeadStyles}>
          {columns.map((col, colIndex) => (
            <TableCell
              key={colIndex}
              sx={{
                minWidth: col.minWidth || '65px',
                p: col.headerPadding || 0
              }}
              align={col.textAlign || 'left'}
            >
              {col.header}
            </TableCell>
          ))}
        </TableRow>
      </TableHead>
      <TableBody>
        {data.map((row, rowIndex) => (
          <TableRow key={rowIndex} sx={rowBodyStyles}>
            {columns.map((col, colIndex) => (
              <TableCell
                key={colIndex}
                sx={cellBodyStyles}
                align={col.textAlign || 'left'}
              >
                {col.render ? col.render(row[col.key], row) : row[col.key]}
              </TableCell>
            ))}
          </TableRow>
        ))}
      </TableBody>
    </Table>
  );
}
