import * as React from 'react';
import {
  GridToolbarContainer,
  GridToolbarColumnsButton,
  GridToolbarFilterButton,
  GridToolbarExport,
  GridToolbarDensitySelector
} from '@mui/x-data-grid';

export default function CustomToolbar(props: any) {
  return (
    <GridToolbarContainer sx={{ justifyContent: 'flex-start' }}>
      <GridToolbarColumnsButton />
      <GridToolbarFilterButton />
      <GridToolbarDensitySelector />
      <GridToolbarExport
        csvOptions={{
          fileName: 'CyHy Dashboard ' + props.exportTitle
        }}
        printOptions={{ disableToolbarButton: true }}
      />
      {props.children}
    </GridToolbarContainer>
  );
}
