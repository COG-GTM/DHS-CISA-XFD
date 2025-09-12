import React from 'react';
import { Box, Button } from '@mui/material';
import { useAuthContext } from 'context/AuthContext';
import MatomoLogo from '../../../src/assets/matomo-logo.png';
import ScansWidget from './Widgets/ScansWidget';

const MetricsDashboard: React.FC = () => {
  const { user } = useAuthContext();

  return (
    <Box p={2}>
      {user?.user_type === 'globalAdmin' && (
        <Box sx={{ display: 'flex', justifyContent: 'flex-start', mb: 2 }}>
          <Button
            variant="contained"
            sx={{
              backgroundColor: '#005EA2',
              color: '#fff',
              '&:hover': { backgroundColor: '#004B87' },
              display: 'flex',
              alignItems: 'center',
              gap: 1
            }}
            onClick={() => window.open('/matomo', '_blank')}
          >
            <img
              src={MatomoLogo}
              alt="Matomo"
              style={{ height: 24, width: 24 }}
            />
            Matomo
          </Button>
        </Box>
      )}
      <ScansWidget />
    </Box>
  );
};

export default MetricsDashboard;
