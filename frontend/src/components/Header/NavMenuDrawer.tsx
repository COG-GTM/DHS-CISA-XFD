import * as React from 'react';
import { NavLink } from 'react-router-dom';
import {
  Box,
  Divider,
  Drawer,
  List,
  ListItem,
  ListItemButton,
  ListItemText
} from '@mui/material';

interface MenuItemType {
  menuItemTitle: string;
  path?: string;
  objectStoreParams?: { bucket_name: string; object_key: string };
  users?: number;
  onClick?: () => void; // For logout or custom actions
}

interface NavMenuDrawerProps {
  toggleDrawer: (open: boolean) => () => void;
  openDrawer: boolean;
  menuItems: { [section: string]: MenuItemType[] }[];
  onMenuItemClick?: (item: MenuItemType) => void;
}

export const NavMenuDrawer: React.FC<NavMenuDrawerProps> = ({
  toggleDrawer,
  openDrawer,
  menuItems,
  onMenuItemClick
}) => {
  const handleMenuItemClick = (item: MenuItemType) => {
    if (item.onClick) {
      item.onClick();
      toggleDrawer(false)();
      return;
    }
    if (item.objectStoreParams && onMenuItemClick) {
      onMenuItemClick(item);
      toggleDrawer(false)();
      return;
    }
    // For links, just close the drawer (navigation handled by NavLink or <a>)
    toggleDrawer(false)();
  };

  const DrawerList = (
    <Box
      sx={{ width: 250 }}
      role="presentation"
      onKeyDown={(e) => {
        if (e.key === 'Escape') toggleDrawer(false)();
      }}
    >
      <Box sx={{ height: '100px' }} />
      <nav aria-label="Main navigation">
        <List>
          {menuItems.map((section, index) => {
            const entries = Object.entries(section);
            if (entries.length === 0) return null;

            const [, items] = entries[0];

            return (
              <React.Fragment key={index}>
                {items.map((item, subIndex) => {
                  // If the item has an onClick (e.g., logout), use it directly
                  if (item.onClick) {
                    return (
                      <ListItem
                        key={`${index}-${subIndex}`}
                        disablePadding
                        role="none"
                      >
                        <ListItemButton
                          onClick={() => handleMenuItemClick(item)}
                          role="menuitem"
                          aria-label={item.menuItemTitle}
                        >
                          <ListItemText primary={item.menuItemTitle} />
                        </ListItemButton>
                      </ListItem>
                    );
                  }

                  // If the item is an object store link
                  if (item.objectStoreParams) {
                    return (
                      <ListItem
                        key={`${index}-${subIndex}`}
                        disablePadding
                        role="none"
                      >
                        <ListItemButton
                          onClick={() => handleMenuItemClick(item)}
                          role="menuitem"
                          aria-label={item.menuItemTitle}
                        >
                          <ListItemText primary={item.menuItemTitle} />
                        </ListItemButton>
                      </ListItem>
                    );
                  }

                  // External link
                  if (item.path?.startsWith('http')) {
                    return (
                      <ListItem
                        key={`${index}-${subIndex}`}
                        disablePadding
                        role="none"
                      >
                        <ListItemButton
                          component="a"
                          href={item.path}
                          target="_blank"
                          rel="noopener noreferrer"
                          role="menuitem"
                          aria-label={item.menuItemTitle}
                          onClick={toggleDrawer(false)}
                        >
                          <ListItemText primary={item.menuItemTitle} />
                        </ListItemButton>
                      </ListItem>
                    );
                  }

                  // Internal link (default)
                  return (
                    <ListItem
                      key={`${index}-${subIndex}`}
                      disablePadding
                      role="none"
                    >
                      <ListItemButton
                        component={NavLink}
                        to={item.path ?? '#'}
                        role="menuitem"
                        aria-label={item.menuItemTitle}
                        onClick={toggleDrawer(false)}
                      >
                        <ListItemText primary={item.menuItemTitle} />
                      </ListItemButton>
                    </ListItem>
                  );
                })}
                <Divider />
              </React.Fragment>
            );
          })}
        </List>
      </nav>
    </Box>
  );

  return (
    <Drawer
      open={openDrawer}
      onClose={toggleDrawer(false)}
      anchor="right"
      role="dialog"
      aria-label="Navigation menu"
    >
      {DrawerList}
    </Drawer>
  );
};
