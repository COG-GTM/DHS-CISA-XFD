import React, { useCallback, useMemo, useState, useEffect } from 'react';
import { useAuthContext } from 'context';
import {
  Autocomplete,
  Box,
  Button,
  Checkbox,
  Divider,
  FormControlLabel,
  FormGroup,
  List,
  ListItem,
  TextField
} from '@mui/material';
import { useStaticsContext } from 'context/StaticsContext';
import {
  ORGANIZATION_EXCLUSIONS
  // REGIONAL_USER_CAN_SEARCH_OTHER_REGIONS
} from 'hooks/useUserTypeFilters';
import { SearchBar } from './SearchBar';
import { useHistory, useLocation } from 'react-router-dom';
import { matchPath } from 'utils/matchPath';

const GLOBAL_ADMIN = 3;
const REGIONAL_ADMIN = 2;
const STANDARD_USER = 1;

// Swap this value to allow regional admin to filter on regions that aren't their own
export const toggleRegionalUserType = true;

export const REGION_FILTER_KEY = 'organization.region_id';
export const ORGANIZATION_FILTER_KEY = 'organization_id';

export interface OrganizationShallow {
  region_id: string;
  name: string;
  id: string;
  root_domains: string[];
}

interface RegionAndOrganizationFiltersProps {
  addFilter: (
    name: string,
    value: any,
    filterType: 'all' | 'any' | 'none'
  ) => void;
  removeFilter: (
    name: string,
    value: any,
    filterType: 'all' | 'any' | 'none'
  ) => void;
  filters: any[];
  setSearchTerm: (s: string, opts?: any) => void;
  search_term: string;
}

export const RegionAndOrganizationFilters: React.FC<
  RegionAndOrganizationFiltersProps
> = ({
  addFilter,
  removeFilter,
  filters,
  search_term: domainSearchTerm,
  setSearchTerm: setDomainSearchTerm
}) => {
  const { setShowMaps, user, apiPost } = useAuthContext();
  const { regions } = useStaticsContext();
  const [search_term, setSearchTerm] = useState<string>('');
  const [orgResults, setOrgResults] = useState<OrganizationShallow[]>([]);
  const [isOrgOpen, setIsOrgOpen] = useState(false);
  const [isRegOpen, setIsRegOpen] = useState(false);

  let userLevel = 0;
  if (user && user.isRegistered) {
    if (user.user_type === 'standard') {
      userLevel = STANDARD_USER;
    } else if (user.user_type === 'globalAdmin') {
      userLevel = GLOBAL_ADMIN;
    } else if (
      user.user_type === 'regionalAdmin' ||
      user.user_type === 'globalView'
    ) {
      userLevel = REGIONAL_ADMIN;
    }
  }
  const searchOrganizations = useCallback(
    async (search_term: string, regions?: string[]) => {
      try {
        const results = await apiPost<{
          body: { hits: { hits: { _source: OrganizationShallow }[] } };
        }>('/search/organizations', {
          body: {
            search_term,
            regions
          }
        });

        const orgs = results.body.hits.hits.map((hit) => hit._source);
        // Filter out organizations that match the exclusions
        const refinedOrgs = orgs.filter((org) => {
          let exlude = false;
          ORGANIZATION_EXCLUSIONS.forEach((exc) => {
            if (org.name.toLowerCase().includes(exc)) {
              exlude = true;
            }
          });
          return !exlude;
        });
        // Filter out organizations that are already in the filters
        const filteredOrgs = refinedOrgs.filter(
          (org) =>
            !filters.find(
              (filter) =>
                filter.field === ORGANIZATION_FILTER_KEY &&
                filter.values.find(
                  (value: { id: string }) => value.id === org.id
                )
            )
        );
        // Sort filtered orgs by name
        const sortedOrgs = filteredOrgs.sort((a, b) =>
          a.name.localeCompare(b.name)
        );

        // Utility function to replce HTML encodings
        const decodeHtml = (org_name: string): string => {
          const encodings: { [key: string]: string } = {
            '&amp;': '&',
            '&lt;': '<',
            '&gt;': '>',
            '&quot;': '"',
            '&#039;': "'"
          };
          return org_name.replace(/&amp;|&lt;|&gt;|&quot;|&#039;/g, (m) => {
            return encodings[m];
          });
        };
        // Decode HTML encodings in org names
        sortedOrgs.forEach((org) => {
          org.name = decodeHtml(org.name);
        });

        setOrgResults(sortedOrgs);
      } catch (e) {
        console.log(e);
      }
    },
    [apiPost, setOrgResults, filters]
  );

  const regionFilterValues = useMemo(() => {
    const regionFilter = filters.find(
      (filter) => filter.field === REGION_FILTER_KEY
    );
    if (regionFilter !== undefined) {
      return regionFilter.values as string[];
    }
    return null;
  }, [filters]);

  const handleCheckboxChange = (region_id: string) => {
    if (regionFilterValues?.includes(region_id)) {
      removeFilter(REGION_FILTER_KEY, region_id, 'any');
    } else {
      addFilter(REGION_FILTER_KEY, region_id, 'any');
    }
  };

  const handleTextChange = (v: string) => {
    setSearchTerm(v);
  };

  useEffect(() => {
    searchOrganizations(search_term, regionFilterValues ?? []);
  }, [searchOrganizations, search_term, regionFilterValues]);

  const organizationsInFilters = useMemo(() => {
    const orgsFilter = filters.find(
      (filter) => filter.field === ORGANIZATION_FILTER_KEY
    );
    if (orgsFilter !== undefined) {
      return orgsFilter.values as OrganizationShallow[];
    } else {
      return null;
    }
  }, [filters]);

  // const showUsersRegionDisabled = useMemo(() => {
  //   return (
  //     (userLevel === STANDARD_USER ||
  //       (!REGIONAL_USER_CAN_SEARCH_OTHER_REGIONS &&
  //         userLevel !== GLOBAL_ADMIN)) &&
  //     user?.region_id
  //   );
  // }, [user?.region_id, userLevel]);

  const regionExistsInFilters = useCallback(
    (region_id: string) => {
      return regionFilterValues?.includes(region_id);
    },
    [regionFilterValues]
  );
  const history = useHistory();
  const location = useLocation();

  const handleAddOrganization = (org: OrganizationShallow) => {
    if (org) {
      const exists = organizationsInFilters?.find((o) => o.id === org.id);
      if (exists) {
        removeFilter(ORGANIZATION_FILTER_KEY, org, 'any');
      } else {
        addFilter(ORGANIZATION_FILTER_KEY, org, 'any');
      }
      setSearchTerm('');
      setIsOrgOpen(false);
      if (org.name === 'Election') {
        setShowMaps(true);
      } else {
        setShowMaps(false);
      }
    } else {
    }
  };

  return (
    <>
      <Divider />
      {matchPath(['/inventory'], location.pathname) ? (
        <Box padding={2}>
          <SearchBar
            initialValue={domainSearchTerm}
            value={domainSearchTerm}
            onChange={(value) => {
              if (location.pathname !== '/inventory') {
                history.push(`/inventory?q=${value}`);
                setDomainSearchTerm(value, {
                  shouldClearFilters: false,
                  refresh: true
                });
              }
              setDomainSearchTerm(value, {
                shouldClearFilters: false
              });
            }}
          />
        </Box>
      ) : (
        <></>
      )}
      <Box padding={2}>
        <Autocomplete
          onInputChange={(e, v) => {
            if (e && e.type === 'change') {
              handleTextChange(v);
            }
          }}
          // inputValue={search_term}
          disableClearable
          disabled={!userLevel || userLevel !== GLOBAL_ADMIN}
          open={isRegOpen}
          onOpen={() => {
            setIsRegOpen(true);
          }}
          options={regions}
          onChange={(e, v) => {
            setTimeout(() => {
              handleCheckboxChange(v);
            }, 250);
            return;
          }}
          getOptionLabel={(option) => `Region ${option}`}
          ListboxProps={{
            sx: {
              ':active': {
                bgcolor: 'transparent'
              }
            }
          }}
          renderOption={(params, option) => {
            return (
              <li
                {...params}
                style={{ pointerEvents: 'none', padding: 0 }}
                key={`region-filter-item-${option}`}
              >
                <Button
                  sx={{
                    pointerEvents: 'auto',
                    height: '100%',
                    width: '100%',
                    display: 'flex',
                    textAlign: 'left',
                    justifyContent: 'start',
                    fontWeight: 400,
                    color: 'black',
                    textTransform: 'none'
                  }}
                  id="search-region-button"
                  onClick={() =>
                    setTimeout(() => {
                      handleCheckboxChange(option);
                    }, 250)
                  }
                >
                  {`Region ${option}`}
                </Button>
              </li>
            );
          }}
          // isOptionEqualToValue={(option, value) =>
          //   option?.name === value?.name
          // }
          renderInput={(params) => (
            <TextField
              {...params}
              label={
                userLevel === GLOBAL_ADMIN
                  ? 'Select Region'
                  : `Region ${user?.region_id}`
              }
              value={search_term}
              defaultValue={user?.region_id}
              onBlur={() => setIsRegOpen(false)}
              placeholder="Search Region"
            />
          )}
        />
        <List>
          {userLevel === GLOBAL_ADMIN &&
            regions.map((region) => {
              return (
                <RegionItem
                  key={`region-item-${region}`}
                  handleChange={handleCheckboxChange}
                  region_id={region}
                  checked={regionExistsInFilters(region) ?? false}
                />
              );
            })}
          {/* )} */}
        </List>
      </Box>
      {/* Need to reconcile type issues caused by adding freeSolo prop */}
      <Box padding={2}>
        <Autocomplete
          onInputChange={(e, v) => {
            if (e && e.type === 'change') {
              handleTextChange(v);
            }
          }}
          inputValue={search_term}
          // freeSolo
          disableClearable
          disabled={userLevel === STANDARD_USER}
          open={isOrgOpen}
          onOpen={() => {
            setIsOrgOpen(true);
          }}
          options={orgResults}
          onChange={(e, v) => {
            setTimeout(() => {
              handleAddOrganization(v);
            }, 250);
            return;
          }}
          getOptionLabel={(option) => option.name}
          ListboxProps={{
            sx: {
              ':active': {
                bgcolor: 'transparent'
              }
            }
          }}
          renderOption={(params, option) => {
            return (
              <li
                {...params}
                style={{ pointerEvents: 'none', padding: 0 }}
                key={option.id}
              >
                <Button
                  sx={{
                    pointerEvents: 'auto',
                    height: '100%',
                    width: '100%',
                    display: 'flex',
                    textAlign: 'left',
                    justifyContent: 'start',
                    fontWeight: 400,
                    color: 'black',
                    textTransform: 'none'
                  }}
                  id="search-org-button"
                  onClick={() =>
                    setTimeout(() => {
                      handleAddOrganization(option);
                    }, 250)
                  }
                >
                  {option.name}
                </Button>
              </li>
            );
          }}
          isOptionEqualToValue={(option, value) => option?.name === value?.name}
          renderInput={(params) => (
            <TextField
              {...params}
              label="Search Organizations"
              onBlur={() => setIsOrgOpen(false)}
              helperText={
                userLevel === REGIONAL_ADMIN || GLOBAL_ADMIN
                  ? 'This filter, by default, displays data for all organinzations in your region. Use this filter to select one or multiple organizations.'
                  : ''
              }
            />
          )}
        />
        {userLevel !== STANDARD_USER && (
          <List sx={{ width: '100%' }}>
            {organizationsInFilters?.map((org) => {
              return (
                <ListItem key={org.id} sx={{ padding: '0px' }}>
                  <FormGroup>
                    <FormControlLabel
                      sx={{ padding: '0px' }}
                      // disabled={userLevel === STANDARD_USER}
                      label={org?.name}
                      control={<Checkbox />}
                      checked={true}
                      onChange={() => {
                        const exists = organizationsInFilters.find(
                          (organization) => organization.id === org.id
                        );
                        if (exists) {
                          removeFilter(ORGANIZATION_FILTER_KEY, org, 'any');
                        } else {
                          addFilter(ORGANIZATION_FILTER_KEY, org, 'any');
                        }
                      }}
                    />
                  </FormGroup>
                </ListItem>
              );
            })}
          </List>
        )}
      </Box>
    </>
  );
};

interface RegionItemProps {
  region_id: string;
  handleChange: (region_id: string) => void;
  checked: boolean;
}

const RegionItem: React.FC<RegionItemProps> = ({
  region_id: region,
  handleChange,
  checked
}) => {
  return (
    <ListItem sx={{ padding: '0px' }} key={`region-filter-item-${region}`}>
      <FormGroup>
        <FormControlLabel
          control={<Checkbox />}
          label={`Region ${region}`}
          checked={checked}
          onChange={() => {
            handleChange(region);
          }}
          sx={{ padding: '0px' }}
        />
      </FormGroup>
    </ListItem>
  );
};
