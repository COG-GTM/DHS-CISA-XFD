type VulnScanSummary = {
  summary_date: string;

  asset_count: number;
  scanned_asset_count: number;

  none_kev_count: number;
  low_kev_count: number;
  medium_kev_count: number;
  high_kev_count: number;
  critical_kev_count: number;

  none_severity_count: number;
  low_severity_count: number;
  medium_severity_count: number;
  high_severity_count: number;
  critical_severity_count: number;

  unique_none_severity_count: number;
  unique_low_severity_count: number;
  unique_medium_severity_count: number;
  unique_high_severity_count: number;
  unique_critical_severity_count: number;

  false_positive_count: number;
};

type vulnScanDataTransformedType = {
  vulnScanSummary: {
    hostScan: string;
    vulnerabilityScan: string;
    assetsOwned: number;
    assetsScanned: number;
  }[];
  vulnScanKeyMetrics: { title: string; value: number }[];
};

export const transformVulnScanData = (data: {
  vuln_scan_summaries: VulnScanSummary[];
}): vulnScanDataTransformedType => {
  if (!data.vuln_scan_summaries || data.vuln_scan_summaries.length === 0) {
    return { vulnScanSummary: [], vulnScanKeyMetrics: [] }; // return empty arrays if no data
  }

  // Find the object with the latest summary_date
  const latestSummary = data.vuln_scan_summaries.reduce(
    (latest, current) =>
      new Date(current.summary_date) > new Date(latest.summary_date)
        ? current
        : latest,
    data.vuln_scan_summaries[0]
  );

  const {
    asset_count,
    scanned_asset_count,
    none_kev_count,
    low_kev_count,
    medium_kev_count,
    high_kev_count,
    critical_kev_count,
    none_severity_count,
    low_severity_count,
    medium_severity_count,
    high_severity_count,
    critical_severity_count,
    unique_none_severity_count,
    unique_low_severity_count,
    unique_medium_severity_count,
    unique_high_severity_count,
    unique_critical_severity_count,
    false_positive_count
  } = latestSummary;

  return {
    vulnScanSummary: [
      {
        hostScan: 'date - date',
        vulnerabilityScan: 'date - date',
        assetsOwned: asset_count ?? 0,
        assetsScanned: scanned_asset_count ?? 0
      }
    ],
    vulnScanKeyMetrics: [
      {
        title: 'Detected Kevs',
        value:
          (none_kev_count ?? 0) +
          (low_kev_count ?? 0) +
          (medium_kev_count ?? 0) +
          (high_kev_count ?? 0) +
          (critical_kev_count ?? 0)
      },
      {
        title: 'Detected Vulnerabilities',
        value:
          (none_severity_count ?? 0) +
          (low_severity_count ?? 0) +
          (medium_severity_count ?? 0) +
          (high_severity_count ?? 0) +
          (critical_severity_count ?? 0)
      },
      {
        title: 'Distinct Vulnerabilities',
        value:
          (unique_none_severity_count ?? 0) +
          (unique_low_severity_count ?? 0) +
          (unique_medium_severity_count ?? 0) +
          (unique_high_severity_count ?? 0) +
          (unique_critical_severity_count ?? 0)
      },
      {
        title: 'False Positives',
        value: false_positive_count ?? 0
      }
    ]
  };
};
