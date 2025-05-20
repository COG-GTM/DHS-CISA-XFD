import React from 'react';
import { useFilterDrawerContext } from 'context/FilterDrawerContext';
import { Button, Stack } from '@mui/material';
import { useTheme } from '@mui/material/styles';
import { FilterAlt } from '@mui/icons-material';
import { matchPath } from 'utils/matchPath';
import { useLocation } from 'react-router-dom';

const FilterDrawerToggle: React.FC = () => {
  const { isFilterDrawerOpen, setIsFilterDrawerOpen } =
    useFilterDrawerContext();
  const theme = useTheme();
  const { pathname } = useLocation();

  const handleToggle = () => {
    setIsFilterDrawerOpen(!isFilterDrawerOpen);
  };

  return (
    <Stack
      sx={{
        maxWidth: '1152px',
        margin: 'auto',
        paddingTop: 2,
        px: {
          xs: 0,
          sm: 0,
          md: 1,
          lg: 1,
          xl: 0
        }
      }}
    >
      <Stack
        direction="row"
        spacing={2}
        alignItems="center"
        justifyContent="space-between"
      >
        <Button
          variant="contained"
          onClick={handleToggle}
          sx={{
            backgroundColor: theme.palette.primary.main,
            color: theme.palette.common.white,
            '&:hover': {
              backgroundColor: theme.palette.primary.dark
            }
          }}
          startIcon={<FilterAlt />}
        >
          {matchPath(['/inventory'], pathname) ? 'Search & Filter' : 'Filter'}
        </Button>
      </Stack>
    </Stack>
  );
};

export default FilterDrawerToggle;
