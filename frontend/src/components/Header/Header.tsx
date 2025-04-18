import React from 'react';
import { useAuthContext } from 'context';
import {
  useUserLevel,
  GLOBAL_ADMIN,
  REGIONAL_ADMIN,
  STANDARD_USER
} from 'hooks/useUserLevel';
import { AppBar, Box, Toolbar, Typography } from '@mui/material';
import cisaLogo from 'assets/cisaSeal.svg';
import { NavMenuButton } from './NavMenuButton';

interface MenuItemType {
  menuItemTitle: string;
  path: string;
  users?: number;
  onClick?: any;
}

export const Header: React.FC = () => {
  const { logout } = useAuthContext();
  const { userLevel } = useUserLevel();
  const adminHubMenuItems: MenuItemType[] = [
    {
      menuItemTitle: 'Admin Tools',
      path: '/admin-tools',
      users: GLOBAL_ADMIN
    },
    {
      menuItemTitle: 'User Registration',
      path: '/region-admin-dashboard',
      users: REGIONAL_ADMIN
    },
    {
      menuItemTitle: 'Manage Organizations',
      path: '/organizations',
      users: REGIONAL_ADMIN
    },
    {
      menuItemTitle: 'Manage Users',
      path: '/users',
      users: REGIONAL_ADMIN
    }
  ].filter(({ users }) => users <= userLevel);

  const userMenuItems: MenuItemType[] = [
    {
      menuItemTitle: 'Account Settings',
      path: '/settings',
      users: STANDARD_USER
    },
    {
      menuItemTitle: 'Logout',
      path: '/settings',
      users: STANDARD_USER,
      onClick: logout
    }
  ].filter(({ users }) => users <= userLevel);

  // TODO: Add path for below menu items
  const vulnScanningMenuItems: MenuItemType[] = [
    {
      menuItemTitle: 'Overview',
      path: '/',
      users: STANDARD_USER
    },
    {
      menuItemTitle: 'Vulnerability Scanning',
      path: '#',
      users: STANDARD_USER
    }
  ].filter(({ users }) => users <= userLevel);

  const supportMenuItems: MenuItemType[] = [
    {
      menuItemTitle: 'Report Bug',
      path: '#',
      users: STANDARD_USER
    },
    {
      menuItemTitle: 'Send Feedback',
      path: '#',
      users: STANDARD_USER
    }
  ].filter(({ users }) => users <= userLevel);

  const learningCenterMenuItems: MenuItemType[] = [
    {
      menuItemTitle: 'Glossary',
      path: '#',
      users: STANDARD_USER
    },
    {
      menuItemTitle: 'FAQ',
      path: '#',
      users: STANDARD_USER
    },
    {
      menuItemTitle: 'CISA Resources',
      path: '#',
      users: STANDARD_USER
    }
  ].filter(({ users }) => users <= userLevel);

  const inventoryMenuItems: MenuItemType[] = [
    {
      menuItemTitle: 'Inventory',
      path: '#',
      users: STANDARD_USER
    }
  ].filter(({ users }) => users <= userLevel);

  const allMenuItems: MenuItemType[] = [
    ...vulnScanningMenuItems,
    ...inventoryMenuItems,
    ...(userLevel === STANDARD_USER ? [] : adminHubMenuItems),
    ...supportMenuItems,
    ...learningCenterMenuItems,
    ...userMenuItems
  ];

  const headerLogo = (
    <Box
      sx={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'left',
        width: '100%',
        ml: { md: 'none', lg: 4, xl: 10 },
        transition: 'margin-left 0.3s ease-in-out'
      }}
    >
      <Box component="img" src={cisaLogo} sx={{ height: 60 }} alt="C Logo" />
      <Typography
        variant="largeBody"
        sx={{
          fontSize: '1.375rem',
          fontWeight: 'bold',
          ml: 1,
          color: 'primary.dark'
        }}
      >
        CyHy Dashboard
      </Typography>
    </Box>
  );

  return (
    <AppBar
      position="static"
      elevation={0}
      sx={{ backgroundColor: 'neutrals.white' }}
    >
      <Toolbar>
        {headerLogo}
        {userLevel > 0 && (
          <>
            <Box
              sx={{ flexGrow: 2, display: 'flex', justifyContent: 'center' }}
            >
              <NavMenuButton
                menuItems={vulnScanningMenuItems}
                title="Vulnerability Scanning"
              />
              <NavMenuButton title="Inventory" path="/inventory" />
              <NavMenuButton
                menuItems={learningCenterMenuItems}
                title="Learning Center"
              />
            </Box>
            <Box
              sx={{
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'flex-end',
                width: '100%',
                mr: { md: 'none', lg: 4, xl: 10 },
                transition: 'margin-right 0.3s ease-in-out'
              }}
            >
              <NavMenuButton menuItems={supportMenuItems} title="Support" />
              {userLevel > 1 && (
                <NavMenuButton
                  menuItems={adminHubMenuItems}
                  title="Admin Hub"
                />
              )}
              <NavMenuButton menuItems={userMenuItems} title="My Account" />
              <NavMenuButton menuItems={allMenuItems} title="Mobile View" />
            </Box>
          </>
        )}
      </Toolbar>
    </AppBar>
  );
};
