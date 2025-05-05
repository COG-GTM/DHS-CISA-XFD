export interface VulnerabilityScanSummary {
  host_summaries: [
    {
      id: number;
      summary_date: string;
      start_date: string;
      end_date: string;
      organization: string;
      host_done_count: number;
      host_waiting_count: number;
      host_running_count: number;
      host_ready_count: number;
      up_host_count: number;
      down_host_count: number;
    }
  ];
  port_scan_summaries: [
    {
      id: number;
      start_date: string;
      end_date: string;
      summary_date: string;
      organization: string;
      open_port_count: number;
      risky_port_count: number;
      nmi_service_count: number;
      unique_ip_count: number;
      unique_service_count: number;
    }
  ];
  port_scan_service_summaries: [
    {
      id: number;
      start_date: string;
      end_date: string;
      summary_date: string;
      organization: string;
      service_name: string;
      open_port_count: number;
      risky_ports: [];
      unique_service_count: number;
    }
  ];
  vuln_scan_summaries: [
    {
      id: number;
      summary_date: string;
      start_date: string;
      end_date: string;
      organization: string;
      asset_count: number;
      false_positive_count: number;
      vulnerable_host_count: number;
      scanned_asset_count: number;
      unique_service_count: number;
      unique_none_severity_count: number;
      unique_low_severity_count: number;
      unique_medium_severity_count: number;
      unique_high_severity_count: number;
      unique_critical_severity_count: number;
      risky_services_count: number;
      unsupported_software_count: number;
      unique_os_count: number;
      none_severity_count: number;
      low_severity_count: number;
      medium_severity_count: number;
      high_severity_count: number;
      critical_severity_count: number;
      critical_max_age: number;
      high_max_age: number;
      none_kev_count: number;
      low_kev_count: number;
      medium_kev_count: number;
      high_kev_count: number;
      critical_kev_count: number;
      kev_max_age: number;
      one_to_five_vulns_count: number;
      six_to_nine_vulns_count: number;
      ten_plus_vulns_count: number;
      top_5_occurring_cves: [
        {
          count: number;
          cve_string: string;
          vuln_name: string;
          cvss_base_score: number;
          severity_string: string;
        }
      ];
      top_5_occurring_kevs: [
        {
          count: number;
          cve_string: string;
          vuln_name: string;
          cvss_base_score: number;
          severity_string: string;
        }
      ];
      included_tickets: [{}];
      top_5_risky_hosts: [{}];
    }
  ];
}
