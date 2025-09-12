// import React from 'react';
// import Notifications from 'pages/Notifications';
// import ScansView from 'pages/Scans/ScansView';
// import ScanTasksView from 'pages/Scans/ScanTasksView';
// import Metrics from '../../components/Metrics/MetricsDashboard';
// import QueueMonitorView from 'pages/Scans/QueueMonitorView';
// import { Box, Button, Container, Tab } from '@mui/material';
// import { TabContext, TabList, TabPanel } from '@mui/lab';
// import { Logs } from 'components/Logs/Logs';
// import { useAuthContext } from 'context/AuthContext';

// export const AdminTools: React.FC = () => {
//   const [value, setValue] = React.useState('1');
//   const { user } = useAuthContext(); // get user from context

//   const handleChange = (event: React.SyntheticEvent, new_value: string) => {
//     setValue(new_value);
//   };
//   return (
//     <Container maxWidth="xl" sx={{ py: 1 }}>
//       <Box sx={{ width: '100%', typography: 'body1' }}>
//         {/* Matomo button at top left, only for globalAdmin */}
//         {user?.user_type === 'globalAdmin' && (
//           <Box sx={{ display: 'flex', justifyContent: 'flex-start', mb: 2 }}>
//             <Button
//               variant="contained"
//               sx={{
//                 backgroundColor: '#005EA2',
//                 color: '#fff',
//                 '&:hover': { backgroundColor: '#004B87' }
//               }}
//               onClick={() => window.open('/matomo', '_blank')}
//             >
//               Matomo
//             </Button>
//           </Box>
//         )}
//         <TabContext value={value}>
//           <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
//             <TabList onChange={handleChange} aria-label="lab API tabs example">
//               <Tab label="Scans" value="1" />
//               <Tab label="Scan History" value="2" />
//               <Tab label="Queue Monitoring" value="3" />
//               <Tab label="Notifications" value="4" />
//               <Tab label="User Logs" value="5" />
//               <Tab label="Metrics" value="6" />
//             </TabList>
//           </Box>
//           <TabPanel value="1">
//             <ScansView />
//           </TabPanel>
//           <TabPanel value="2">
//             <ScanTasksView />
//           </TabPanel>
//           <TabPanel value="3">
//             <QueueMonitorView />
//           </TabPanel>
//           <TabPanel value="4">
//             <Notifications />
//           </TabPanel>
//           <TabPanel value="5">
//             <Logs />
//           </TabPanel>
//           <TabPanel value="6">
//             <Metrics />
//           </TabPanel>
//         </TabContext>
//       </Box>
//     </Container>
//   );
// };

// export default AdminTools;

import React from 'react';
import Notifications from 'pages/Notifications';
import ScansView from 'pages/Scans/ScansView';
import ScanTasksView from 'pages/Scans/ScanTasksView';
import Metrics from '../../components/Metrics/MetricsDashboard';
import QueueMonitorView from 'pages/Scans/QueueMonitorView';
import { Box, Button, Container, Tab } from '@mui/material';
import { TabContext, TabList, TabPanel } from '@mui/lab';
import { Logs } from 'components/Logs/Logs';
import { useAuthContext } from 'context/AuthContext';
import MatomoLogo from '../../../src/assets/matomo-logo.png'; // adjust path if needed

export const AdminTools: React.FC = () => {
  const [value, setValue] = React.useState('1');
  const { user } = useAuthContext();

  const handleChange = (event: React.SyntheticEvent, new_value: string) => {
    setValue(new_value);
  };

  return (
    <Container maxWidth="xl" sx={{ py: 1 }}>
      <Box sx={{ width: '100%', typography: 'body1' }}>
        <TabContext value={value}>
          <Box sx={{ borderBottom: 1, borderColor: 'divider' }}>
            <TabList onChange={handleChange} aria-label="lab API tabs example">
              <Tab label="Scans" value="1" />
              <Tab label="Scan History" value="2" />
              <Tab label="Queue Monitoring" value="3" />
              <Tab label="Notifications" value="4" />
              <Tab label="User Logs" value="5" />
              <Tab label="Metrics" value="6" />
              <Tab label="Matomo" value="7" /> {/* New tab next to Metrics */}
            </TabList>
          </Box>
          <TabPanel value="1">
            <ScansView />
          </TabPanel>
          <TabPanel value="2">
            <ScanTasksView />
          </TabPanel>
          <TabPanel value="3">
            <QueueMonitorView />
          </TabPanel>
          <TabPanel value="4">
            <Notifications />
          </TabPanel>
          <TabPanel value="5">
            <Logs />
          </TabPanel>
          <TabPanel value="6">
            <Metrics />
          </TabPanel>
          <TabPanel value="7">
            {/* Matomo button and functionality */}
            {user?.user_type === 'globalAdmin' ? (
              <Box
                sx={{ display: 'flex', justifyContent: 'flex-start', mt: 2 }}
              >
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
            ) : (
              <Box sx={{ mt: 2 }}>You do not have access to Matomo.</Box>
            )}
          </TabPanel>
        </TabContext>
      </Box>
    </Container>
  );
};

export default AdminTools;
