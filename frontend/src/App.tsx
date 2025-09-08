// frontend/src/App.tsx
import React, { useEffect } from 'react';
import {
  BrowserRouter as Router,
  Switch,
  Route,
  useLocation
} from 'react-router-dom';
import { API, Auth } from 'aws-amplify';
import { AuthContextProvider, CFThemeProvider, SearchProvider } from 'context';
import {
  MatomoProvider,
  createInstance,
  useMatomo
} from '@jonkoops/matomo-tracker-react';
import {
  AdminTools,
  AuthCreateAccount,
  AuthLogin,
  Domain,
  Domains,
  Feeds,
  LoginGovCallback,
  OktaCallback,
  RegionUsers,
  Reports,
  Organization,
  Organizations,
  SearchPage,
  Settings,
  TermsOfUse,
  Users,
  Vulnerabilities,
  Vulnerability
} from 'pages';
import { LayoutWithSearch, RouteGuard } from 'components';
import './styles.scss';
import { Authenticator } from '@aws-amplify/ui-react';
import { StaticsContextProvider } from 'context/StaticsContextProvider';
import { SavedSearchContextProvider } from 'context/SavedSearchContextProvider';
import { FilterDrawerContextProvider } from 'context/FilterDrawerContextProvider';
import { VulnerabilityScanWithSearch } from 'pages/VulnerabilityScanDash/VulnerabilityScan';

// Inspector overlay; Vite plugin must also be enabled in dev
import { Inspector, type InspectParams } from 'react-dev-inspector';

API.configure({
  endpoints: [{ name: 'crossfeed', endpoint: import.meta.env.VITE_API_URL }]
});

if (import.meta.env.VITE_USE_COGNITO) {
  Auth.configure({
    region: import.meta.env.VITE_EMAIL_REGION,
    userPoolId: import.meta.env.VITE_USER_POOL_ID,
    userPoolWebClientId: import.meta.env.VITE_USER_POOL_CLIENT_ID
  });
}

const instance = createInstance({
  urlBase: `${import.meta.env.VITE_API_URL}/matomo`,
  siteId: 1,
  disabled: false,
  heartBeat: { active: true, seconds: 15 },
  linkTracking: false
});

const LinkTracker = () => {
  const location = useLocation();
  const { trackPageView } = useMatomo();
  useEffect(() => trackPageView({}), [location, trackPageView]);
  return null;
};

// Local absolute frontend root (set in .env)
const LOCAL_FRONTEND_ROOT =
  (import.meta.env.VITE_LOCAL_FRONTEND_ROOT as string) || '';
const CONTAINER_ROOT = '/app';

// Map container path to local path and open in VS Code via URL scheme
function openInVSCode({ codeInfo }: InspectParams) {
  // Handle potential missing codeInfo
  if (!codeInfo) return;

  let abs = codeInfo.absolutePath;

  // Create an absolute container path if only relative is provided
  if (!abs && codeInfo.relativePath) {
    abs = `${CONTAINER_ROOT}/${codeInfo.relativePath}`.replace(/\/{2,}/g, '/');
  }

  // Handle potential missing abs path result
  if (!abs) return;

  // Translate container path to local machine root
  if (LOCAL_FRONTEND_ROOT && abs.startsWith(CONTAINER_ROOT)) {
    abs = abs.replace(CONTAINER_ROOT, LOCAL_FRONTEND_ROOT);
  }

  // Line/Column info
  const line = codeInfo.lineNumber ?? 1;
  const col = codeInfo.columnNumber ?? 1;

  // Open VS Code (host must have VS Code installed to handle the scheme)
  const url = `vscode://file${abs}:${line}:${col}`;
  window.location.href = encodeURI(url);
}

const App: React.FC = () => (
  <MatomoProvider value={instance}>
    <Router>
      <CFThemeProvider>
        <AuthContextProvider>
          <Authenticator.Provider>
            <StaticsContextProvider>
              <SavedSearchContextProvider>
                <SearchProvider>
                  <FilterDrawerContextProvider>
                    <LayoutWithSearch>
                      <LinkTracker />

                      {import.meta.env.DEV && (
                        <Inspector
                          // Use the key names expected by the library
                          // keys={['control', 'shift', 'meta', 'c']}
                          // Override with custom editor
                          disableLaunchEditor
                          onClickElement={openInVSCode}
                        />
                      )}

                      <Switch>
                        <RouteGuard
                          exact
                          path="/"
                          unauth={AuthLogin}
                          component={VulnerabilityScanWithSearch}
                        />
                        <Route
                          exact
                          path="/login-gov-callback"
                          component={LoginGovCallback}
                        />
                        <Route
                          exact
                          path="/okta-callback"
                          component={OktaCallback}
                        />
                        <Route
                          exact
                          path="/create-account"
                          component={AuthCreateAccount}
                        />
                        <Route exact path="/terms" component={TermsOfUse} />
                        <RouteGuard
                          exact
                          path="/inventory"
                          component={SearchPage}
                          permissions={[
                            'globalView',
                            'regionalAdmin',
                            'standard'
                          ]}
                        />
                        <RouteGuard
                          path="/inventory/domain/:domainId"
                          component={Domain}
                          permissions={[
                            'globalView',
                            'regionalAdmin',
                            'standard'
                          ]}
                        />
                        <RouteGuard
                          path="/inventory/domains"
                          component={Domains}
                        />
                        <RouteGuard
                          path="/VSDashboard"
                          component={VulnerabilityScanWithSearch}
                        />
                        <RouteGuard
                          exact
                          path="/inventory/vulnerabilities"
                          component={Vulnerabilities}
                          permissions={[
                            'globalView',
                            'regionalAdmin',
                            'standard'
                          ]}
                        />
                        <RouteGuard
                          path="/inventory/vulnerabilities/grouped"
                          component={(props) => (
                            <Vulnerabilities {...props} group_by="title" />
                          )}
                          permissions={[
                            'globalView',
                            'regionalAdmin',
                            'standard'
                          ]}
                        />
                        <RouteGuard
                          path="/inventory/vulnerability/:vulnerabilityId"
                          component={Vulnerability}
                          permissions={[
                            'globalView',
                            'regionalAdmin',
                            'standard'
                          ]}
                        />
                        <RouteGuard
                          path="/feeds"
                          component={Feeds}
                          permissions={['globalView']}
                        />
                        <RouteGuard
                          path="/reports"
                          component={Reports}
                          permissions={[
                            'globalView',
                            'regionalAdmin',
                            'standard'
                          ]}
                        />
                        <RouteGuard
                          path="/admin-tools"
                          component={AdminTools}
                          permissions={['globalAdmin']}
                        />
                        <RouteGuard
                          path="/organizations/:organizationId"
                          component={Organization}
                          permissions={['globalView', 'regionalAdmin']}
                        />
                        <RouteGuard
                          path="/organizations"
                          component={Organizations}
                          permissions={[
                            'globalView',
                            'regionalAdmin',
                            'standard'
                          ]}
                        />
                        <RouteGuard
                          path="/users"
                          component={Users}
                          permissions={['globalView', 'regionalAdmin']}
                        />
                        <RouteGuard
                          path="/settings"
                          component={Settings}
                          permissions={[
                            'globalView',
                            'regionalAdmin',
                            'standard'
                          ]}
                        />
                        <RouteGuard
                          path="/region-admin-dashboard"
                          component={RegionUsers}
                          permissions={['regionalAdmin', 'globalView']}
                        />
                      </Switch>
                    </LayoutWithSearch>
                  </FilterDrawerContextProvider>
                </SearchProvider>
              </SavedSearchContextProvider>
            </StaticsContextProvider>
          </Authenticator.Provider>
        </AuthContextProvider>
      </CFThemeProvider>
    </Router>
  </MatomoProvider>
);

export default App;
