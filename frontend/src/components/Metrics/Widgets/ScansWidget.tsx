import React, { useEffect, useCallback, useState, useMemo } from 'react';
import {
  Box,
  Paper,
  Table,
  TableBody,
  TableCell,
  TableContainer,
  TableHead,
  TableRow,
  Tooltip
} from '@mui/material';
import { ResponsiveLine } from '@nivo/line';
import dayjs from 'dayjs';
import { useAuthContext } from 'context';
import * as MetricsStyles from '../style';
import {
  ScanDetails,
  ScanSummaries,
  OrgCountByStatus,
  ScanSummary
} from '../../../types/metrics';

const generateDateRange = (days: number): string[] => {
  const today = dayjs().startOf('day');
  return Array.from({ length: days }, (_, i) =>
    today.subtract(days - 1 - i, 'day').format('YYYY-MM-DD')
  );
};

const STATUS_COLORS: Record<number, string> = {
  1: '#5c5c5c', // Cool gray/blue for informational
  2: '#1a7f37', // Green for success
  3: '#125ea4', // Blue for redirects
  4: '#c75200', // Orange for client errors
  5: '#a51414' // Red for server errors
};

const getStatusColor = (status: number): string => {
  const category = Math.floor(status / 100);
  return STATUS_COLORS[category] || '#5c5c5c';
};

const ScansWidget: React.FC = () => {
  const { apiGet } = useAuthContext();
  const [scanSummaries, setScanSummaries] = useState<ScanSummaries | null>(
    null
  );
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);
  const [scanDetails, setScanDetails] = useState<ScanDetails | null>(null);

  const { cardRoot, cardSmall, cardTitle, header, body } =
    MetricsStyles.classesMetrics;

  const fetchScanSummaries = useCallback(async () => {
    const result = await apiGet('/metrics/scans');
    setScanSummaries(result || null);
  }, [apiGet]);

  const fetchScanDetails = useCallback(
    async (scanId: string) => {
      const result = await apiGet(`/metrics/scans/${scanId}`);
      setScanDetails(result || null);
    },
    [apiGet]
  );

  useEffect(() => {
    fetchScanSummaries();
  }, [fetchScanSummaries]);

  const handleScanClick = (scanId: string) => {
    setSelectedScanId(scanId);
    fetchScanDetails(scanId);
  };

  const allStatusCodes: number[] = useMemo(() => {
    return scanSummaries?.scans
      ? Array.from(
          new Set(
            scanSummaries.scans.flatMap((scan: ScanSummary) =>
              scan.org_counts_by_status.map(
                (status: OrgCountByStatus) => status.http_status
              )
            )
          )
        ).sort((a, b) => a - b)
      : [];
  }, [scanSummaries]);

  const metricsWindowDays = useMemo(() => {
    return scanSummaries?.metrics_window_days ?? 'N';
  }, [scanSummaries]);

  const dateRange = useMemo(
    () =>
      scanDetails ? generateDateRange(scanDetails.metrics_window_days) : [],
    [scanDetails]
  );

  const normalizedDetails = useMemo(() => {
    if (!scanDetails) return [];

    return scanDetails.daily_status_counts.map((status) => {
      const countMap = Object.fromEntries(
        status.daily_counts.map((d) => [d.date, d.count])
      );

      const series = dateRange.map((date) => ({
        x: date,
        y: countMap[date] ?? 0
      }));

      return {
        http_status: status.http_status,
        total: series.reduce((acc, d) => acc + d.y, 0),
        lineData: [
          {
            id: status.http_status.toString(),
            data: series,
            color: getStatusColor(status.http_status)
          }
        ]
      };
    });
  }, [scanDetails, dateRange]);

  const statusCategoryLabels: Record<number, string> = {
    1: 'Informational',
    2: 'Success',
    3: 'Redirect',
    4: 'Client Error',
    5: 'Server Error'
  };

  const getCategoryCounts = (codes: number[]) => {
    return codes.reduce(
      (acc, code) => {
        const cat = Math.floor(code / 100);
        acc[cat] = (acc[cat] || 0) + 1;
        return acc;
      },
      {} as Record<number, number>
    );
  };

  const categoryCounts = getCategoryCounts(allStatusCodes);

  return (
    <Paper
      elevation={0}
      className={cardRoot}
      style={{ padding: '0.5rem 1.25rem' }}
    >
      <div className={cardSmall}>
        <div className={header}>
          <h2
            style={{ fontSize: '1.25rem', fontWeight: 600, color: '#07648D' }}
          >
            Scan Success Metrics
          </h2>
        </div>
        <div className={body}>
          {scanSummaries?.scans?.length ? (
            <>
              <h3 style={{ margin: 0 }}>Scan Result Summary</h3>
              <h4 style={{ fontWeight: 'normal', margin: 0 }}>
                Organization count per scan for each HTTP Status Code
              </h4>
              <TableContainer>
                <Table size="small" aria-label="Scan status table">
                  <TableHead>
                    <TableRow>
                      <TableCell
                        align="center"
                        colSpan={2}
                        style={{ borderBottom: '1px solid #ddd' }}
                      ></TableCell>
                      {Object.entries(categoryCounts).map(
                        ([cat, count], idx, arr) => {
                          const isLast = idx === arr.length - 1;
                          return (
                            <TableCell
                              key={`label-${cat}`}
                              align="center"
                              colSpan={count}
                              style={{
                                fontWeight: 'bold',
                                fontSize: '0.75rem',
                                borderBottom: '1px solid #ddd',
                                borderRight: !isLast
                                  ? '1px solid #ddd'
                                  : undefined
                              }}
                            >
                              {statusCategoryLabels[Number(cat)] || 'Other'}
                            </TableCell>
                          );
                        }
                      )}
                    </TableRow>

                    <TableRow>
                      <TableCell
                        align="center"
                        style={{
                          fontWeight: 'bold',
                          borderBottom: '1px solid #ddd'
                        }}
                      >
                        Scan Name
                      </TableCell>
                      <TableCell
                        align="center"
                        style={{
                          fontWeight: 'bold',
                          borderBottom: '1px solid #ddd'
                        }}
                      >
                        Total Orgs
                      </TableCell>
                      {allStatusCodes.map((code) => (
                        <TableCell
                          align="center"
                          key={code}
                          style={{
                            fontWeight: 'bold',
                            borderBottom: '1px solid #ddd',
                            borderRight: undefined
                          }}
                        >
                          {code}
                        </TableCell>
                      ))}
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {(scanSummaries?.scans ?? []).map((scan) => {
                      const countMap = Object.fromEntries(
                        scan.org_counts_by_status.map((s: OrgCountByStatus) => [
                          s.http_status,
                          s.org_count
                        ])
                      );

                      return (
                        <Tooltip
                          key={scan.id}
                          title={
                            <span className={cardTitle}>
                              Click to view scan metrics
                            </span>
                          }
                          placement="right"
                          arrow
                        >
                          <TableRow
                            role="button"
                            tabIndex={0}
                            onClick={() => handleScanClick(scan.id)}
                            onKeyDown={(e) => {
                              if (e.key === 'Enter' || e.key === ' ') {
                                e.preventDefault();
                                handleScanClick(scan.id);
                              }
                            }}
                          >
                            <TableCell align="center">{scan.name}</TableCell>
                            <TableCell align="center">
                              {scan.total_orgs}
                            </TableCell>
                            {allStatusCodes.map((code) => (
                              <TableCell align="center" key={code}>
                                {countMap[code] ?? 0}
                              </TableCell>
                            ))}
                          </TableRow>
                        </Tooltip>
                      );
                    })}
                  </TableBody>
                </Table>
              </TableContainer>
            </>
          ) : (
            <h3>No scans available</h3>
          )}

          {selectedScanId && scanDetails && (
            <Box mt={4}>
              <h3 style={{ margin: 0 }}>
                {scanDetails.name} HTTP Status Trends (Last{' '}
                {scanDetails.metrics_window_days} Days)
              </h3>
              <TableContainer>
                <Table size="small">
                  <TableHead>
                    <TableRow>
                      <TableCell style={{ fontWeight: 'bold' }}>
                        Status Code
                      </TableCell>
                      <TableCell style={{ fontWeight: 'bold' }}>
                        Sparkline
                      </TableCell>
                      <TableCell align="right" style={{ fontWeight: 'bold' }}>
                        Total
                      </TableCell>
                    </TableRow>
                  </TableHead>
                  <TableBody>
                    {normalizedDetails.map((row) => (
                      <TableRow key={row.http_status}>
                        <TableCell>{row.http_status}</TableCell>
                        <TableCell>
                          <div style={{ height: '40px', width: '100%' }}>
                            <ResponsiveLine
                              data={row.lineData}
                              margin={{
                                top: 10,
                                right: 10,
                                bottom: 10,
                                left: 10
                              }}
                              xScale={{ type: 'point' }}
                              yScale={{
                                type: 'linear',
                                stacked: false,
                                min: 0
                              }}
                              axisTop={null}
                              axisRight={null}
                              axisBottom={null}
                              axisLeft={null}
                              enableGridX={false}
                              enableGridY={false}
                              enablePoints={false}
                              colors={(d) => getStatusColor(Number(d.id))}
                              lineWidth={2}
                              isInteractive={false}
                              useMesh={true}
                            />
                          </div>
                        </TableCell>
                        <TableCell align="right">{row.total}</TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              </TableContainer>
            </Box>
          )}
        </div>
      </div>
    </Paper>
  );
};

export default ScansWidget;
