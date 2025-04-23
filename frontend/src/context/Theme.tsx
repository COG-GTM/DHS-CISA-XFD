import React from 'react';
import {
  createTheme,
  ThemeProvider,
  StyledEngineProvider,
  Theme
} from '@mui/material/styles';

declare module '@mui/material/styles' {
  interface BreakpointOverrides {
    mds: true;
  }
  interface BreakpointsOptions {
    values: {
      xs: number;
      sm: number;
      mds: number;
      md: number;
      lg: number;
      xl: number;
    };
  }
  interface Palette {
    disabled: Palette['primary'];
    neutrals: Palette['primary'];
  }

  interface PaletteOptions {
    disabled?: PaletteOptions['primary'];
    neutrals?: PaletteOptions['primary'];
  }

  interface PaletteColor {
    darker?: string;
    white?: string;
    black?: string;
  }

  interface SimplePaletteColorOptions {
    darker?: string;
    white?: string;
    black?: string;
  }

  interface TypographyVariants {
    boldBody: React.CSSProperties;
    largeBody: React.CSSProperties;
    globalNav: React.CSSProperties;
    link: React.CSSProperties;
    miniStatCallout: React.CSSProperties;
    statCallout: React.CSSProperties;
    uiElementsI: React.CSSProperties;
    uiElementsII: React.CSSProperties;
    uiElementsIII: React.CSSProperties;
  }
  interface TypographyVariantsOptions {
    boldBody: React.CSSProperties;
    largeBody: React.CSSProperties;
    globalNav: React.CSSProperties;
    link: React.CSSProperties;
    miniStatCallout: React.CSSProperties;
    statCallout: React.CSSProperties;
    uiElementsI: React.CSSProperties;
    uiElementsII: React.CSSProperties;
    uiElementsIII: React.CSSProperties;
  }
}

declare module '@mui/material/Typography' {
  interface TypographyPropsVariantOverrides {
    boldBody: true;
    largeBody: true;
    globalNav: true;
    link: true;
    miniStatCallout: true;
    statCallout: true;
    uiElementsI: true;
    uiElementsII: true;
    uiElementsIII: true;
  }
  interface TypographyPropsColorOverrides {
    disabled: true;
  }
}

const theme = createTheme({
  breakpoints: {
    values: {
      xs: 0,
      sm: 600,
      mds: 750,
      md: 900,
      lg: 1200,
      xl: 1536
    }
  },
  components: {
    MuiButton: {
      variants: [
        {
          props: { variant: 'contained' },
          style: ({ theme }: { theme: Theme }) => ({
            backgroundColor: theme.palette.primary.dark,
            color: theme.palette.primary.white,
            '&:hover': {
              backgroundColor: theme.palette.primary.darker
            },
            height: '40px',
            padding: '10px 16px 10px 16px',
            borderRadius: '4px',
            ...theme.typography.button
          })
        },
        {
          props: { variant: 'text' },
          style: ({ theme }: { theme: Theme }) => ({
            backgroundColor: 'transparent',
            color: theme.palette.primary.dark,
            '&:hover': {
              color: theme.palette.primary.darker
            },
            fontSize: '1rem',
            textTransform: 'none'
          })
        }
      ]
    },
    MuiIconButton: {
      styleOverrides: {
        root: ({ theme }) => ({
          color: theme.palette.primary.dark,
          '&:hover': {
            color: theme.palette.primary.darker
          }
        })
      }
    },
    MuiLink: {
      styleOverrides: {
        root: ({ theme }) => ({
          color: theme.palette.primary.dark,
          '&:hover': {
            color: theme.palette.primary.darker
          }
        })
      }
    },
    MuiMenuItem: {
      styleOverrides: {
        root: ({ theme }) => ({
          color: theme.palette.primary.dark,
          fontSize: '1rem',
          '&:hover': {
            backgroundColor: theme.palette.primary.light,
            color: theme.palette.primary.dark
          },
          '&.Mui-selected': {
            backgroundColor: theme.palette.primary.light,
            color: theme.palette.primary.dark
          }
        })
      }
    },
    MuiListItemText: {
      styleOverrides: {
        primary: ({ theme }) => ({
          fontSize: '1rem',
          color: theme.palette.primary.dark
        })
      }
    },
    MuiListItemButton: {
      styleOverrides: {
        root: ({ theme }) => ({
          '&:hover': {
            backgroundColor: theme.palette.primary.light
          },
          '&.Mui-selected': {
            backgroundColor: theme.palette.primary.light
          }
        })
      }
    }

    // To-do: Re-enable this after clarification with Design Team
    // MuiChip: {
    //   styleOverrides: {
    //     root: {
    //       borderRadius: '4px',
    //       fontSize: '1.167rem',
    //       fontWeight: 'medium',
    //       height: '24px',
    //       padding: '2px 14px 2px 14px',
    //       '&:hover': {
    //         backgroundColor: '#ECF7FF'
    //       }
    //     }
    //   }
    // }
  },

  palette: {
    primary: {
      main: '#0078AE',
      light: '#ECF7FF',
      dark: '#005288',
      darker: '#002B45'
    },
    secondary: {
      main: '#EC7633',
      light: '#FFB38A',
      dark: '#C33200',
      darker: '#731A00'
    },
    error: {
      main: '#C41230'
    },
    success: {
      main: '#5E9732'
    },
    background: {
      default: '#FFFFFF'
    },
    disabled: {
      main: '#BDBDBD', // Set your desired disabled color here
      contrastText: '#FFFFFF' // Optional: define text color for the disabled state
    },
    neutrals: {
      main: '#646566',
      light: '#A9AEB1',
      dark: '#2F2F30',
      white: '#FFFFFF',
      black: '#000000'
    }
  },
  typography: {
    fontFamily: 'source sans pro, sans-serif',
    body1: {
      fontSize: '1.167rem',
      fontWeight: 'regular',
      textTransform: 'none'
    },
    boldBody: {
      fontSize: '1.167rem',
      fontWeight: 'bold',
      textTransform: 'none'
    },
    largeBody: {
      fontSize: '1.333rem',
      fontWeight: 'regular',
      textTransform: 'none'
    },
    button: {
      fontSize: '1.167rem',
      fontWeight: 'medium',
      textTransform: 'uppercase'
    },
    globalNav: {
      fontSize: '1rem',
      fontWeight: 'medium',
      textTransform: 'none'
    },
    h1: {
      fontSize: '3rem',
      fontWeight: 'bold',
      textTransform: 'none'
    },
    h2: {
      fontSize: '2rem',
      fontWeight: 'medium',
      textTransform: 'none'
    },
    h3: {
      fontSize: '1.5rem',
      fontWeight: 'medium',
      textTransform: 'none'
    },
    link: {
      fontSize: '1.167rem',
      fontWeight: 'medium',
      textDecoration: 'underline'
    },
    miniStatCallout: {
      fontSize: '1.667rem',
      fontWeight: 'medium',
      textTransform: 'uppercase'
    },
    statCallout: {
      fontSize: '3rem',
      fontWeight: 'bold',
      textTransform: 'uppercase'
    },
    uiElementsI: {
      fontSize: '0.833rem',
      fontWeight: 'regular',
      textTransform: 'none'
    },
    uiElementsII: {
      fontSize: '1rem',
      fontWeight: 'medium',
      textTransform: 'none'
    },
    uiElementsIII: {
      fontSize: '1rem',
      fontWeight: 'medium',
      fontStyle: 'italic',
      textTransform: 'none'
    }
  }
});

interface CFThemeProviderProps {
  children: React.ReactNode;
}
export const CFThemeProvider: React.FC<CFThemeProviderProps> = ({
  children
}) => {
  return (
    <StyledEngineProvider injectFirst>
      <ThemeProvider theme={theme}>{children}</ThemeProvider>
    </StyledEngineProvider>
  );
};
