import React from 'react';
import { Link, Tooltip, Typography } from '@mui/material';

interface TruncatedLinkProps {
  text: string | null;
  linkHandler: (value: string) => void;
}

const TruncatedLink = ({ text = '', linkHandler }: TruncatedLinkProps) => {
  const safeText = text || '';
  const showTooltip = safeText.length > 0;
  return (
    <Tooltip
      title={showTooltip ? safeText : ''}
      placement={'right'}
      enterDelay={300}
      leaveDelay={200}
      describeChild
      slotProps={{
        tooltip: {
          sx: {
            backgroundColor: 'transparent',
            boxShadow: 'none',
            padding: 0
          }
        }
      }}
    >
      <Link
        onClick={() => linkHandler(safeText)}
        aria-label={`View details for: ${safeText}`}
        sx={{
          display: '-webkit-box',
          WebkitLineClamp: 2,
          WebkitBoxOrient: 'vertical',
          overflow: 'hidden',
          textOverflow: 'ellipsis',
          lineHeight: '1.5',
          maxHeight: '3em',
          cursor: 'pointer'
        }}
      >
        <Typography variant="body2" component="span" color="inherit">
          {safeText}
        </Typography>
      </Link>
    </Tooltip>
  );
};

export default TruncatedLink;
