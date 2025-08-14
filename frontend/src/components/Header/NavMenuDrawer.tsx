import * as React from 'react';
import { NavLink } from 'react-router-dom';
import {
  Box,
  Collapse,
  Divider,
  Drawer,
  List,
  ListItem,
  ListItemButton,
  ListItemIcon,
  ListItemText
} from '@mui/material';
import KeyboardArrowDownIcon from '@mui/icons-material/KeyboardArrowDown';
import { MenuItemType } from './Header';

interface NavMenuDrawerProps {
  toggleDrawer: (open: boolean) => () => void;
  openDrawer: boolean;
  menuItems: { [section: string]: MenuItemType[] }[];
  onMenuItemClick?: (item: MenuItemType) => Promise<void>;
}

export const NavMenuDrawer: React.FC<NavMenuDrawerProps> = ({
  toggleDrawer,
  openDrawer,
  menuItems,
  onMenuItemClick
}) => {
  const [openCollapse, setOpenCollapse] = React.useState<string | false>(false);
  const DrawerList = (
    <Box
      sx={{ width: 250, pt: 3 }}
      role="presentation"
      onKeyDown={(e) => {
        if (e.key === 'Escape') toggleDrawer(false)();
      }}
    >
      <nav aria-label="Main navigation">
        <List>
          {menuItems.map((section, index) => {
            const entries = Object.entries(section);
            if (entries.length === 0) return null;

            const [, items] = entries[0];

            return (
              <React.Fragment key={index}>
                {items &&
                  items.length > 0 &&
                  items.map((item, subIndex) => {
                    const isHttpLink = item.path?.startsWith('http');
                    const isMailtoLink = item.path?.startsWith('mailto:');
                    const isSubMenu =
                      item.subMenuItems && item.subMenuItems.length > 0;

                    // 1. onClick handler
                    if (item.onClick) {
                      return (
                        <ListItem
                          key={`${index}-${subIndex}`}
                          disablePadding
                          role="none"
                        >
                          <ListItemButton
                            role="menuitem"
                            aria-label={item.menuItemTitle}
                            onClick={() => {
                              item.onClick && item.onClick();
                              toggleDrawer(false)();
                            }}
                          >
                            <ListItemText primary={item.menuItemTitle} />
                          </ListItemButton>
                        </ListItem>
                      );
                    }

                    // 2. Object store handler
                    if (item.objectStoreParams && onMenuItemClick) {
                      return (
                        <ListItem
                          key={`${index}-${subIndex}`}
                          disablePadding
                          role="none"
                        >
                          <ListItemButton
                            role="menuitem"
                            aria-label={item.menuItemTitle}
                            onClick={async () => {
                              await onMenuItemClick(item);
                              toggleDrawer(false)();
                            }}
                          >
                            <ListItemText primary={item.menuItemTitle} />
                          </ListItemButton>
                        </ListItem>
                      );
                    }

                    // 3. External http link
                    if (isHttpLink) {
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

                    // 4. External mailto link
                    if (isMailtoLink) {
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
                          >
                            <ListItemText primary={item.menuItemTitle} />
                          </ListItemButton>
                        </ListItem>
                      );
                    }
                    // 5. Internal link
                    if (item.path) {
                      return (
                        <ListItem
                          key={`${index}-${subIndex}`}
                          disablePadding
                          role="none"
                        >
                          <ListItemButton
                            component={NavLink}
                            to={item.path}
                            role="menuitem"
                            aria-label={item.menuItemTitle}
                            onClick={toggleDrawer(false)}
                          >
                            <ListItemText primary={item.menuItemTitle} />
                          </ListItemButton>
                        </ListItem>
                      );
                    }

                    // 6. Submenu
                    if (isSubMenu && onMenuItemClick) {
                      return (
                        <React.Fragment key={`${index}-${subIndex}`}>
                          <ListItem disablePadding role="none">
                            <ListItemButton
                              onClick={() => {
                                setOpenCollapse(
                                  openCollapse === `${index}-${subIndex}`
                                    ? false
                                    : `${index}-${subIndex}`
                                );
                              }}
                              role="menuitem"
                              aria-haspopup="true"
                              aria-label={item.menuItemTitle}
                            >
                              <ListItemText primary={item.menuItemTitle} />
                              <ListItemIcon>
                                <KeyboardArrowDownIcon fontSize="small" />
                              </ListItemIcon>
                            </ListItemButton>
                          </ListItem>
                          <Collapse
                            in={openCollapse === `${index}-${subIndex}`}
                            timeout="auto"
                            unmountOnExit
                          >
                            <List component="div" sx={{ pl: 1 }}>
                              {item.subMenuItems?.map(
                                (subItem, subSubIndex) => (
                                  <ListItem
                                    key={`${index}-${subIndex}-${subSubIndex}`}
                                    disablePadding
                                    role="none"
                                  >
                                    <ListItemButton
                                      role="menuitem"
                                      aria-label={subItem.menuItemTitle}
                                      onClick={async () => {
                                        await onMenuItemClick(item);
                                        toggleDrawer(false)();
                                      }}
                                    >
                                      <ListItemText
                                        primary={subItem.menuItemTitle}
                                      />
                                    </ListItemButton>
                                  </ListItem>
                                )
                              )}
                            </List>
                          </Collapse>
                        </React.Fragment>
                      );
                    }
                    return null;
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
      ModalProps={{
        keepMounted: true
      }}
      slotProps={{
        paper: {
          sx: {
            zIndex: (theme) => theme.zIndex.modal + 1
          }
        }
      }}
    >
      {DrawerList}
    </Drawer>
  );
};
