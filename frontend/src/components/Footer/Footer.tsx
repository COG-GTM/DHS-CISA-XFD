import React from 'react';
import { Link as RouterLink } from 'react-router-dom';
import { Box, Grid, Link, Stack } from '@mui/material';
import { useAuthContext } from 'context';
import logo from '../../assets/cyhydashboard.svg';
import * as FooterStyles from './styleFooter';

export const CrossfeedFooter: React.FC = (props) => {
  const { logout, user } = useAuthContext();
  const FooterRoot = FooterStyles.FooterRoot;
  const footerClasses = FooterStyles.footerClasses;

  return (
    <FooterRoot>
      <Box className={footerClasses.footerBox}>
        <Grid className={footerClasses.footerContainer} container>
          <Grid className={footerClasses.footerLogo} item xs={12} sm={3}>
            <Stack direction="row" spacing={1}>
              <Link
                to="/"
                aria-label={`CyHy Dashboard Icon Navigate Home`}
                component={RouterLink}
              >
                <img src={logo} alt="CyHy Dashboard Icon Navigate Home" />
              </Link>
            </Stack>
          </Grid>
          {user && (
            <Grid className={footerClasses.footerNavItem} item xs={12} sm={2}>
              <Link
                className={footerClasses.footerNavLink}
                to="/"
                component={RouterLink}
              >
                Home
              </Link>
            </Grid>
          )}
          {/* <Grid className={footerClasses.footerNavItem} item xs={12} sm={2}>
            <p>
              <Link
                className={footerClasses.footerNavLink}
                href="https://docs.crossfeed.cyber.dhs.gov/"
                target="_blank"
              >
                Documentation
              </Link>
            </p>
          </Grid> */}
          <Grid className={footerClasses.footerNavItem} item xs={12} sm={2}>
            <p>
              <Link
                className={footerClasses.footerNavLink}
                href="https://www.cisa.gov"
                target="_blank"
                rel="noopener noreferrer"
              >
                CISA Homepage
              </Link>
            </p>
          </Grid>
          <Grid className={footerClasses.footerNavItem} item xs={12} sm={2}>
            <p>
              <Link
                className={footerClasses.footerNavLink}
                href="mailto:vulnerability@cisa.dhs.gov"
              >
                Contact Us
              </Link>
            </p>
          </Grid>
          {user && (
            <Grid className={footerClasses.footerNavItem} item xs={12} sm={2}>
              <p>
                <Link
                  className={footerClasses.footerNavLink}
                  to="/"
                  onClick={logout}
                  component={RouterLink}
                >
                  Logout
                </Link>
              </p>
            </Grid>
          )}
        </Grid>
      </Box>
    </FooterRoot>
  );
};
