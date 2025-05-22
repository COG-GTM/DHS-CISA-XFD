import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Box, Button, TextField } from '@mui/material';
import Autocomplete from '@mui/material/Autocomplete';
import { useUserLevel } from 'hooks/useUserLevel';
import { useAuthContext } from 'context';
import { useStaticsContext } from 'context/StaticsContext';
import { ORGANIZATION_EXCLUSIONS } from 'hooks/useUserTypeFilters';
import { useLocation } from 'react-router-dom';
import { OrganizationShallow } from './RegionAndOrganizationFilters';

const GLOBAL_ADMIN = 3;
const REGIONAL_ADMIN = 2;
const STANDARD_USER = 1;

// Swap this value to allow regional admin to filter on regions that aren't their own
export const toggleRegionalUserType = true;

export const REGION_FILTER_KEY = 'organization.region_id';
export const ORGANIZATION_FILTER_KEY = 'organization_id';

interface RegionAndOrgFiltersProps {
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
}

export const VSDashRegionAndOrgFilters: React.FC<RegionAndOrgFiltersProps> = ({
  addFilter,
  removeFilter,
  filters
}) => {
  const { setShowMaps, user, apiPost } = useAuthContext();
  const { regions } = useStaticsContext();
  const [search_term, setSearchTerm] = useState<string>('');
  const [orgResults, setOrgResults] = useState<OrganizationShallow[]>([]);
  const [isRegOpen, setIsRegOpen] = useState(false);
  const [isOrgOpen, setIsOrgOpen] = useState(false);
  const [selectedRegion, setSelectedRegion] = useState<string | undefined>(
    undefined
  );
  const [selectedOrg, setSelectedOrg] = useState<
    OrganizationShallow | undefined
  >(undefined);

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

  //   const handleCheckboxChange = (region_id: string) => {
  //     if (regionFilterValues?.includes(region_id)) {
  //       removeFilter(REGION_FILTER_KEY, region_id, 'any');
  //     } else {
  //       addFilter(REGION_FILTER_KEY, region_id, 'any');
  //     }
  //   };

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

  //   const regionExistsInFilters = useCallback(
  //     (region_id: string) => {
  //       return regionFilterValues?.includes(region_id);
  //     },
  //     [regionFilterValues]
  //   );
  // const history = useHistory();
  //   const location = useLocation();

  //   const handleAddOrganization = (org: OrganizationShallow) => {
  //     if (org) {
  //       const exists = organizationsInFilters?.find((o) => o.id === org.id);
  //       if (exists) {
  //         removeFilter(ORGANIZATION_FILTER_KEY, org, 'any');
  //       } else {
  //         addFilter(ORGANIZATION_FILTER_KEY, org, 'any');
  //       }
  //       setSearchTerm('');
  //       setIsOrgOpen(false);
  //       if (org.name === 'Election') {
  //         setShowMaps(true);
  //       } else {
  //         setShowMaps(false);
  //       }
  //     } else {
  //     }
  //   };

  const handleChangeRegion = (region_id: string) => {
    if (region_id) {
      const existingRegions =
        filters.find((filter) => filter.field === REGION_FILTER_KEY)?.values ||
        [];
      existingRegions.forEach((existingRegion: string) => {
        removeFilter(REGION_FILTER_KEY, existingRegion, 'any');
      });
      addFilter(REGION_FILTER_KEY, region_id, 'any');
      //   setSearchTerm('');
      setIsRegOpen(false);
    }
  };

  const handleChangeOrganization = (org: OrganizationShallow) => {
    if (!org) return;

    const existingFilters =
      filters.find((filter) => filter.field === ORGANIZATION_FILTER_KEY)
        ?.values || [];
    console.log('existingFilters', existingFilters);
    existingFilters.forEach((existingOrg: OrganizationShallow) => {
      removeFilter(ORGANIZATION_FILTER_KEY, existingOrg, 'any');
    });
    addFilter(ORGANIZATION_FILTER_KEY, org, 'any');
    setSearchTerm('');
    setIsOrgOpen(false);
  };

  const userOrg = user?.roles?.map((role) => role.organization.name);
  const userRegion = user?.region_id;
  console.log('userRegion', userRegion);
  return (
    <>
      <Box padding={2}>
        <Autocomplete
          value={selectedRegion}
          onChange={(e, v) => {
            setTimeout(() => {
              setSelectedRegion(v);
              handleChangeRegion(v);
              //   handleCheckboxChange(v);
            }, 250);
            return;
          }}
          onInputChange={(e, v) => {
            if (e && e.type === 'change') {
              handleTextChange(v);
            }
          }}
          //   inputValue={search_term}
          disableClearable
          disabled={!userLevel || userLevel !== GLOBAL_ADMIN}
          open={isRegOpen}
          onOpen={() => {
            setIsRegOpen(true);
          }}
          options={regions}
          getOptionLabel={(option) => `Region ${option}`}
          ListboxProps={{
            sx: {
              ':active': {
                bgcolor: 'transparent'
              },
              overflow: 'auto',
              overscrollBehavior: 'contain'
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
                      setSelectedRegion(option);
                      handleChangeRegion(option);
                      //   handleCheckboxChange(option);
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
                selectedRegion
                  ? `Region ${selectedRegion}`
                  : `Region ${userRegion}`
              }
              value={search_term}
              defaultValue={user?.region_id}
              onBlur={() => setIsRegOpen(false)}
            />
          )}
        />
        {/* Need to reconcile type issues caused by adding freeSolo prop */}
      </Box>
      <Box padding={2}>
        <Autocomplete
          value={selectedOrg}
          onChange={(e, v) => {
            setSelectedOrg(v);
            setTimeout(() => {
              handleChangeOrganization(v);
            }, 250);
            return;
          }}
          //   inputValue={search_term}
          onInputChange={(e, v) => {
            if (e && e.type === 'change') {
              handleTextChange(v);
            }
          }}
          // freeSolo
          disableClearable
          disabled={userLevel === STANDARD_USER}
          open={isOrgOpen}
          onOpen={() => {
            setIsOrgOpen(true);
          }}
          options={orgResults}
          getOptionLabel={(option) => option.name}
          ListboxProps={{
            sx: {
              ':active': {
                bgcolor: 'transparent'
              },
              overflow: 'auto',
              overscrollBehavior: 'contain'
            }
          }}
          renderOption={(params, option) => {
            return (
              <li
                {...params}
                style={{
                  pointerEvents: 'none',
                  padding: 0
                  //   overscrollBehavior: 'contain',
                  //   overflow: 'auto'
                  //   maxHeight: '100vh'
                }}
                key={option.id}
                // height="100vh"
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
                    // overflow: 'hidden',
                    // textOverflow: 'ellipsis',
                    // overscrollBehavior: 'contain'
                  }}
                  id="search-org-button"
                  onClick={() =>
                    setTimeout(() => {
                      setSelectedOrg(option);
                      handleChangeOrganization(option);
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
              label={selectedOrg?.name ? selectedOrg.name : userOrg}
              onBlur={() => setIsOrgOpen(false)}
              helperText={
                userLevel === REGIONAL_ADMIN || GLOBAL_ADMIN
                  ? 'This filter, by default, displays data for all organinzations in your region. Use this filter to select one or multiple organizations.'
                  : ''
              }
            />
          )}
        />
      </Box>
    </>
  );
};
