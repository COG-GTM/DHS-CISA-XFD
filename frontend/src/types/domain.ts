import { Organization } from './organization';
import { Scan } from './scan';
import { Cpe } from './cpe';

export interface Product {
  // Common name
  name: string;
  // Product name
  product?: string;
  // Product vendor
  vendor?: string;
  // Product version
  version: string;
  // Product version revision
  revision?: string;
  // CPE without version (unique identifier)
  cpe?: string;
  // Optional icon
  icon?: string;
  // Optional description
  description?: string;
  // Tags
  tags: string[];
}

export interface Service {
  port: number;
  service: string;
  id: number;
  last_seen: string | null;
  banner: string | null;
  censys_metadata: {
    product: string;
    revision: string;
    description: string;
    version: string;
    manufacturer: string;
  } | null;
  censys_ipv4_results: any;
  intrigue_ident_results: {
    fingerprint: {
      type: string;
      vendor: string;
      product: string;
      version: string;
      update: string;
      tags: string[];
      match_type: string;
      match_details: string;
      hide: boolean;
      cpe: string;
      issue?: string;
      task?: string;
      inference: boolean;
    }[];
    content: {
      type: string;
      name: string;
      hide?: boolean;
      issue?: boolean;
      task?: boolean;
      result?: boolean;
    }[];
  };
  wappalyzer_results: WappalyzerResult[];
  products: Product[];
  productSource: string | null;
  service_source: string | null;
}

export interface Webpage {
  id: string;
  created_at: Date;
  updated_at: Date;
  synced_at: Date | null;
  domain: Domain;
  discovered_by: Scan;
  last_seen: Date | null;
  s3_key: string | null;
  url: string;
  status: number;
  response_size: number | null;
}

export interface Vulnerability {
  id: string;
  domain: Domain;
  created_at: string;
  last_seen: string | null;
  title: string;
  cve: string | null;
  is_kev?: string;
  is_kev_ransomware?: string;
  cwe: string | null;
  cpe: string | null;
  description: string;
  cvss: number | null;
  severity: string | null;
  state: string;
  source: string;
  structured_data: { [x: string]: any };
  substate: string;
  notes: string;
  actions: {
    type: 'state-change' | 'comment';
    state?: string;
    substate?: string;
    value?: string;
    automatic: boolean;
    user_id: string | null;
    userName?: string | null;
    date: string;
  }[];
  references: {
    url: string;
    name: string;
    source: string;
    tags: string[];
  }[];
  service: Service;
  adp_automatable: boolean | null;
  adp_created_at: string | null;
  adp_cve_id: string | null;
  adp_date_updated: string | null;
  adp_exploitation: string | null;
  adp_id: number | null;
  adp_provider: string | null;
  adp_ssvc_timestamp: string | null;
  adp_ssvc_version: string | null;
  adp_technical_impact: string | null;
  adp_title: string | null;
  adp_updated_at: string | null;
  cve_row_id: number | null;
  cve_name: string | null;
  cve_modified_at: Date;
  cve_published_at: Date;
  cve_status: string | null;
  cve_cvss_v2_source: string | null;
  cve_cvss_v2_type: string | null;
  cve_cvss_v2_version: string | null;
  cve_cvss_v2_vector_string: string | null;
  cve_cvss_v2_base_score: string | null;
  cve_cvss_v2_base_severity: string | null;
  cve_cvss_v2_exploitability_score: string | null;
  cve_cvss_v2_impact_score: string | null;
  cve_cvss_v3_source: string | null;
  cve_cvss_v3_type: string | null;
  cve_cvss_v3_version: string | null;
  cve_cvss_v3_vector_string: string | null;
  cve_cvss_v3_base_score: string | null;
  cve_cvss_v3_base_severity: string | null;
  cve_cvss_v3_exploitability_score: string | null;
  cve_cvss_v3_impact_score: string | null;
  cve_cvss_v4_source: string | null;
  cve_cvss_v4_type: string | null;
  cve_cvss_v4_version: string | null;
  cve_cvss_v4_vector_string: string | null;
  cve_cvss_v4_base_score: string | null;
  cve_cvss_v4_base_severity: string | null;
  cve_cvss_v4_exploitability_score: string | null;
  cve_cvss_v4_impact_score: string | null;
  cve_weaknesses: string[] | null;
  cve_cpe_list: Cpe[] | null;
  cpes: Cpe[];
}

export interface Domain {
  id: string;
  name: string;
  ip: string;
  created_at: string;
  updated_at: string;
  screenshot: string | null;
  country: string | null;
  asn: string | null;
  cloud_hosted: boolean;
  services: Service[];
  vulnerabilities: Vulnerability[];
  webpages: Webpage[];
  organization: Organization;
  ssl?: SSLInfo | null;
  censys_certificates_results: any;
  from_root_domain: string | null;
  subdomain_source: string | null;
}

export interface DomainSearchApiResponse {
  id: string;
  name: string;
  ip: string;
  created_at: string;
  updated_at: string;
  country: string | null;
  cloud_hosted: boolean;
  organization: {
    id: string;
    name: string;
  };
  ports_preview: string;
  services_preview: string;
  services_count: number;
  vulnerabilities_count: number;
}

export interface SSLInfo {
  issuerOrg: string | null;
  issuerCN: string | null;
  validTo: string | null;
  validFrom: string | null;
  altNames: string | null;
  protocol: string | null;
  fingerprint: string | null;
  bits: string | null;
}

export interface WappalyzerResult {
  technology?: {
    name?: string;
    categories?: number[];
    slug?: string;
    url?: string[];
    headers?: any[];
    dns?: any[];
    cookies?: any[];
    dom?: any[];
    html?: any[];
    css?: any[];
    certIssuer?: any[];
    robots?: any[];
    meta?: any[];
    scripts?: any[];
    js?: any;
    implies?: any[];
    excludes?: any[];
    icon?: string;
    website?: string;
    cpe?: string;
  };
  pattern?: {
    value?: string;
    regex?: string;
    confidence?: number;
    version?: string;
  };
  // Actual detected version
  version?: string;
}
