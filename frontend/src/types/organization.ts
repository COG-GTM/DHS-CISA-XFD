import { Role } from './role';
import { ScanTask } from './scan-task';
import { Scan } from './scan';

export interface Organization {
  id: string;
  name: string;
  rootDomains: string[];
  ip_blocks: string[];
  userRoles: Role[];
  scanTasks: ScanTask[];
  is_passive: boolean;
  granularScans: Scan[];
  tags: OrganizationTag[];
  parent: Organization | null;
  children: Organization[];
  pending_domains: PendingDomain[];
  country?: string;
  region_id?: string;
  state?: string;
  state_fips?: number;
  state_name?: string;
  county?: string;
  county_fips?: number;
  acronym: string;
  type: string;
  userCount?: number;
  tagNames?: string[];
}

export interface PendingDomain {
  name: string;
  token: string;
}

export interface OrganizationTag {
  id: string;
  name: string;
  tags: OrganizationTag[];
  organizations: Organization[];
  scans: Scan[];
}
