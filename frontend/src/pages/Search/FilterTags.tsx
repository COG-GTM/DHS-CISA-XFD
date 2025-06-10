import React, { useMemo } from 'react';
import { classes, Root } from './Styling/filterTagsStyle';
import { ContextType } from '../../context/SearchProvider';
import { Chip, Stack, Typography, useTheme } from '@mui/material';
import { REGIONAL_ADMIN, useUserLevel } from 'hooks/useUserLevel';
import { STANDARD_USER } from 'context/userStateUtils';
import {
  REGIONAL_USER_CAN_SEARCH_OTHER_REGIONS,
  useUserTypeFilters
} from 'hooks/useUserTypeFilters';
import { useLocation } from 'react-router-dom';
import { FiberManualRecordRounded } from '@mui/icons-material';
import { useAuthContext } from 'context';
import { useStaticsContext } from 'context/StaticsContext';

interface Props {
  filters: ContextType['filters'];
  removeFilter: ContextType['removeFilter'];
}

interface FieldToLabelMap {
  [key: string]: {
    labelAccessor: (t: any) => any;
    filterValueAccssor: (t: any) => any;
    trimAfter?: number;
  };
}

type EllipsisPastIndex<T> = (source: T[], index: number | null) => T[];

const ellipsisPastIndex: EllipsisPastIndex<string> = (source, index) => {
  const DEFAULT_INDEX = 3;
  if (index === null || index === 0) {
    return source.slice(0, DEFAULT_INDEX);
  } else if (source.length > index + 1) {
    const remainder = source.length - index - 1;
    return [...source.slice(0, index + 1), `...+${remainder}`];
  } else {
    return source;
  }
};

const FIELD_TO_LABEL_MAP: FieldToLabelMap = {
  'organization.region_id': {
    labelAccessor: (t) => {
      return 'Region';
    },
    filterValueAccssor: (t) => {
      if (Array.isArray(t)) {
        return t.sort((a: string, b: string) => {
          const numA = parseInt(a, 10);
          const numB = parseInt(b, 10);
          return numA - numB;
        });
      }
      return t;
    },
    trimAfter: 10
  },
  'vulnerabilities.severity': {
    labelAccessor: (t) => {
      return 'Severity';
    },
    filterValueAccssor(t) {
      const severityLevels = [
        'N/A',
        'Low',
        'Medium',
        'High',
        'Critical',
        'Other'
      ];
      if (Array.isArray(t)) {
        return t.sort((a: string, b: string) => {
          const aValue = severityLevels.indexOf(a);
          const bValue = severityLevels.indexOf(b);
          return aValue - bValue;
        });
      }
      return t;
    },
    trimAfter: 3
  },
  ip: {
    labelAccessor: (t) => {
      return 'IP';
    },
    filterValueAccssor(t) {
      if (Array.isArray(t)) {
        return t.sort((a: string, b: string) => {
          return a.localeCompare(b);
        });
      }
      return t;
    }
  },
  name: {
    labelAccessor: (t) => {
      return 'Name';
    },
    filterValueAccssor(t) {
      if (Array.isArray(t)) {
        return t.sort((a: string, b: string) => {
          return a.localeCompare(b);
        });
      }
      return t;
    }
  },
  from_root_domain: {
    labelAccessor: (t) => {
      return 'Root Domain(s)';
    },
    filterValueAccssor(t) {
      if (Array.isArray(t)) {
        return t.sort((a: string, b: string) => {
          return a.localeCompare(b);
        });
      }
      return t;
    }
  },
  organization_id: {
    labelAccessor: (t) => {
      return 'Organization';
    },
    filterValueAccssor: (t) => {
      if (Array.isArray(t)) {
        return t
          .map((org) => org.name)
          .sort((a: string, b: string) => {
            return a.localeCompare(b);
          });
      }
      return t.name;
    },
    trimAfter: 3
  },

  query: {
    labelAccessor: (t) => {
      return 'Query';
    },
    filterValueAccssor(t) {
      return t;
    }
  },
  'services.port': {
    labelAccessor: (t) => {
      return 'Port';
    },
    filterValueAccssor: (t) => {
      if (Array.isArray(t)) {
        return t.sort((a: number, b: number) => {
          return a - b;
        });
      }
      return t;
    },
    trimAfter: 6
  },
  'vulnerabilities.cve': {
    labelAccessor: (t) => {
      return 'CVE';
    },
    filterValueAccssor(t) {
      if (Array.isArray(t)) {
        return t.sort((a: string, b: string) => {
          return a.localeCompare(b);
        });
      }
      return t;
    },
    trimAfter: 10
  }
};

type FlatFilters = {
  field: string;
  label: string;
  onClear?: () => void;
  value: any;
  values: any[];
  type: 'all' | 'none' | 'any';
}[];

const filterOrder = [
  'Region',
  'Organization',
  'IP',
  'Name',
  'Root Domain(s)',
  'Port',
  'CVE',
  'Severity'
];

const sortFiltersByOrder = (filters: FlatFilters) => {
  return filters.sort((a, b) => {
    return filterOrder.indexOf(a.label) - filterOrder.indexOf(b.label);
  });
};

export const FilterTags: React.FC<Props> = ({ filters, removeFilter }) => {
  const { pathname } = useLocation();
  const { regions } = useStaticsContext();
  const { user } = useAuthContext();

  const { userLevel } = useUserLevel();
  const initialFiltersForUser = useUserTypeFilters(regions, user, userLevel);

  const disabledFilters = useMemo(() => {
    if (userLevel === STANDARD_USER) {
      return ['Region', 'Organization'];
    }
    if (userLevel === REGIONAL_ADMIN) {
      return REGIONAL_USER_CAN_SEARCH_OTHER_REGIONS ? [] : ['Region'];
    }
  }, [userLevel]);

  const filtersByColumn: FlatFilters = useMemo(() => {
    const processedFilters = filters.reduce((acc, nextFilter) => {
      const fieldAccessors = FIELD_TO_LABEL_MAP[nextFilter.field] ?? null;
      const sortedValues = fieldAccessors
        ? fieldAccessors.filterValueAccssor(nextFilter.values)
        : nextFilter.values;
      const value = fieldAccessors
        ? ellipsisPastIndex(
            sortedValues,
            fieldAccessors.trimAfter ? fieldAccessors.trimAfter - 1 : null
          ).join(', ')
        : sortedValues.join(', ');
      const label = fieldAccessors
        ? fieldAccessors.labelAccessor(nextFilter)
        : nextFilter.field.split('.').pop();
      return [
        ...acc,
        {
          ...nextFilter,
          value: value,
          label: label
        }
      ];
    }, []);
    return sortFiltersByOrder(processedFilters);
  }, [filters]);

  // New code for handling more complex filters
  // 1. Find all region and org filters
  const regionFilter = filters.find(
    (f) => f.field === 'organization.region_id'
  );
  const orgFilter = filters.find((f) => f.field === 'organization_id');

  const portFilter = filters.find((f) => f.field === 'services.port');
  const cveFilter = filters.find((f) => f.field === 'vulnerabilities.cve');
  const severityFilter = filters.find(
    (f) => f.field === 'vulnerabilities.severity'
  );
  console.log('regionFilter', regionFilter);
  console.log('orgFilter', orgFilter);
  console.log('portFilter', portFilter);
  console.log('cveFilter', cveFilter);
  console.log('severityFilter', severityFilter);

  // 2. Group orgs by region
  let regionOrgMap: Record<string, string[]> = {};
  if (regionFilter && orgFilter && Array.isArray(orgFilter.values)) {
    // orgFilter.values should be array of org objects with .region_id and .name
    regionOrgMap = orgFilter.values.reduce(
      (
        acc: { [x: string]: any[] },
        org: { region_id: string | number; name: any }
      ) => {
        if (!acc[org.region_id]) acc[org.region_id] = [];
        acc[org.region_id].push(org.name);
        return acc;
      },
      {} as Record<string, string[]>
    );
  }

  const FiltersApplied: React.FC = () => {
    const theme = useTheme();
    return (
      <Stack direction="row" alignItems="center" spacing={1}>
        <FiberManualRecordRounded sx={{ color: theme.palette.success.main }} />
        <Typography color="textSecondary">Filters Applied</Typography>
      </Stack>
    );
  };
  const initialFilters = useUserTypeFilters(regions, user, userLevel);
  const nonInitialFilters = filters.filter((currentFilter) => {
    // Find a matching initial filter by field
    const initial = initialFilters.find(
      (initFilter) => initFilter.field === currentFilter.field
    );
    if (!initial) return true; // No initial filter for this field

    // Compare values (assuming arrays of primitives or use a deep equality check for objects)
    const currentVals = Array.isArray(currentFilter.values)
      ? currentFilter.values
      : [currentFilter.values];
    const initialVals = Array.isArray(initial.values)
      ? initial.values
      : [initial.values];

    // Check if every value in currentVals is in initialVals and vice versa
    if (currentVals.length !== initialVals.length) return true;
    return !currentVals.every((val: any) => initialVals.includes(val));
  });

  console.log('nonInitialFilters', nonInitialFilters);
  return (
    <Root aria-live="polite" aria-atomic="true">
      <>
        {nonInitialFilters.length > 0 && <FiltersApplied />}
        {/* {filtersByColumn.length === 0 && pathname === '/inventory' ? (
          <Chip
            color="primary"
            classes={{ root: classes.chip }}
            label="No Filter(s) Applied"
          />
        ) : (
          filtersByColumn.map((filter, idx) => (
            <Chip
              key={idx}
              disabled={disabledFilters?.includes(filter.label)}
              color="primary"
              classes={{ root: classes.chip }}
              label={`${filter.label}: ${filter.value}`}
              onDelete={
                !disabledFilters?.includes(filter.label)
                  ? () => {
                      filter.onClear
                        ? filter.onClear()
                        : filter.values.forEach((val) =>
                            removeFilter(filter.field, val, filter.type)
                          );
                    }
                  : undefined
              }
            />
          ))
        )} */}
        {/* Uncomment this section if you want to display grouped region/org chips*/}
        {/* {regionFilter &&
          Object.entries(regionOrgMap).map(([regionId, orgNames]) => (
            <Chip
              key={regionId}
              color="primary"
              classes={{ root: classes.chip }}
              label={`Region ${regionId}: ${orgNames.join(', ')}`}
              onDelete={() => {
                // Remove both the region and all orgs in that region
                removeFilter(
                  'organization.region_id',
                  regionId,
                  regionFilter.type
                );
                orgNames.forEach((orgName) => {
                  const org = orgFilter.values.find(
                    (o: any) => o.name === orgName
                  );
                  if (org) removeFilter('organization_id', org, orgFilter.type);
                });
              }}
            />
          ))}*/}
        {/* <Stack direction={'row'} alignItems="center" spacing={1}>
          <Typography color="textSecondary">Filters Applied:</Typography> */}
        {/* <Typography>Filters Applied:</Typography> */}
        {/*{regionFilter &&
            Object.entries(regionOrgMap).map(([regionId, orgNames]) => {
              return (
                <>
                  <Typography
                    key={regionId}
                    variant="body2"
                    color="textSecondary"
                    // className={classes.regionOrgLabel}
                  >{`Region ${regionId}- ${orgNames.join(', ')}`}</Typography> */}

        {/* <Chip
              //   key={regionId}
              //   color="primary"
              //   classes={{ root: classes.chip }}
              //   label={`Region ${regionId}: ${orgNames.join(', ')}`}
              //   onDelete={() => {
              //     // Remove both the region and all orgs in that region
              //     removeFilter(
              //       'organization.region_id',
              //       regionId,
              //       regionFilter.type
              //     );
              //     orgNames.forEach((orgName) => {
              //       const org = orgFilter.values.find(
              //         (o: any) => o.name === orgName
              //       );
              //       if (org)
              //         removeFilter('organization_id', org, orgFilter.type);
              //     });
              //   }}
              // />*/}
        {/* </>
              );
            })}
        </Stack> */}
      </>
    </Root>
  );
};
