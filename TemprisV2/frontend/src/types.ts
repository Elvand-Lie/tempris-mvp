// frontend/src/types.ts

export type TargetType = 'ip' | 'hostname' | 'domain';
export type NetworkScope = 'internet' | 'internal';
export type EnvironmentType = 'production' | 'staging' | 'development' | 'test' | 'other';
export type CriticalityType = 'critical' | 'high' | 'medium' | 'low';
export type AssetStatus = 'active' | 'decommissioned';
export type ReachabilityStatus = 'unverified' | 'verified' | 'unreachable';
export type AuthorizationStatus = 'pending' | 'approved' | 'revoked' | 'expired';
export type UserRole = 'analyst' | 'admin' | 'superadmin';
export type ActiveTab = 'assets' | 'collectors' | 'org';

export type CollectorEnrollmentStatus = 'awaiting_enrollment' | 'enrolled';
export type CollectorOperatorStatus = 'active' | 'paused' | 'quarantined' | 'revoked';
export type CollectorConnectionStatus = 'connected' | 'offline';
export type CollectorDerivedStatus =
  | 'awaiting_enrollment'
  | 'connected'
  | 'offline'
  | 'paused'
  | 'quarantined'
  | 'revoked';

export interface PlatformMetadata {
  os?: string;
  os_version?: string;
  hostname?: string;
  architecture?: string;
  [key: string]: any;
}

export interface Collector {
  id: string;
  tenant_id: string;
  name: string;
  description: string | null;
  enrollment_status: CollectorEnrollmentStatus;
  operator_status: CollectorOperatorStatus;
  connection_status: CollectorConnectionStatus;
  status: CollectorDerivedStatus;
  platform_metadata: PlatformMetadata;
  req_rate_per_sec: number;
  public_key?: string | null;
  os?: string | null;
  architecture?: string | null;
  hostname?: string | null;
  version?: string | null;
  enrolled_at?: string | null;
  revoked_at?: string | null;
  server_url?: string | null;
  created_at: string;
  updated_at: string;
}

export interface CollectorCreatePayload {
  name: string;
  description?: string | null;
}

export interface CollectorEnrollmentResponse extends Collector {
  enrollment_code: string;
  enrollment_code_expires_at: string;
}

export interface LoginCredentials {
  email: string;
  password: string;
}

export interface LoginResponse {
  token: string;
  token_type: string;
  expires_in: number;
  tenant_id: string;
  role: string;
}

export interface JwtPayload {
  sub?: string;
  tenant_id?: string;
  role?: UserRole | string;
  iat?: number;
  exp?: number;
  [key: string]: any;
}

export interface UserProfile {
  email: string;
  is_platform_admin: boolean;
}

export interface TenantInfo {
  id: string;
  name: string;
  slug: string;
  status?: string;
  created_at?: string;
}

export interface TenantSessionMetadata extends TenantInfo {
  effective_modules: string[];
  is_platform_admin: boolean;
}

export interface AuthState {
  token: string | null;
  user: UserProfile | null;
  activeTenant: TenantInfo | null;
  effectiveModules: string[];
  currentRole: UserRole;
  metadataLoading: boolean;
  metadataError: string | null;
}

export interface Asset {
  id: string;
  tenant_id: string;
  name: string;
  asset_type: string;
  target_type: TargetType;
  target_value: string;
  normalized_target: string;
  network_scope: NetworkScope;
  environment: EnvironmentType;
  criticality: CriticalityType;
  owner: string | null;
  tags: string[];
  collector_id?: string | null;
  status: AssetStatus;
  reachability_status: ReachabilityStatus;
  verification_source: string | null;
  last_verified_at: string | null;
  created_at: string;
  updated_at: string;
  decommissioned_at: string | null;
}

export interface AssetCreatePayload {
  name: string;
  asset_type: string;
  target_type: TargetType;
  target_value: string;
  network_scope: NetworkScope;
  environment: EnvironmentType;
  criticality: CriticalityType;
  owner?: string | null;
  tags?: string[];
  collector_id?: string | null;
}

export interface AssetUpdatePayload {
  name?: string;
  asset_type?: string;
  target_type?: TargetType;
  target_value?: string;
  network_scope?: NetworkScope;
  environment?: EnvironmentType;
  criticality?: CriticalityType;
  owner?: string | null;
  tags?: string[];
  collector_id?: string | null;
}

export interface TargetCheckPayload {
  target_type: TargetType;
  target_value: string;
  network_scope: NetworkScope;
  collector_id?: string | null;
  correlation_id?: string | null;
}

export interface TargetCheckResponse {
  valid: boolean;
  normalized_target: string;
  address_classification: string;
  network_scope: string;
  reachability_status: ReachabilityStatus;
  verification_source: string | null;
  message: string;
}

export interface ScanAuthorization {
  id: string;
  tenant_id: string;
  asset_id: string;
  target_type: TargetType;
  normalized_target: string;
  network_scope: NetworkScope;
  status: AuthorizationStatus;
  requested_by: string;
  requested_at: string;
  request_reason: string | null;
  approved_by: string | null;
  approved_at: string | null;
  expires_at: string | null;
  revoked_by: string | null;
  revoked_at: string | null;
  revocation_reason: string | null;
}

export interface AssetStats {
  total_assets: number;
  reachable_by_scout: number;
  authorized_to_scan: number;
  pending_authorization: number;
  no_scanner_available: number;
}

export interface CollectorStats {
  total_collectors: number;
  connected_collectors: number;
  awaiting_enrollment: number;
  paused_or_quarantined: number;
}

export type MembershipStatus = 'active' | 'disabled';
export type UserStatus = 'active' | 'pending' | 'disabled';

export interface OrgMember {
  id: string;
  email: string;
  full_name: string | null;
  user_status: UserStatus;
  role: UserRole;
  membership_status: MembershipStatus;
  created_at: string;
}

export interface MemberCreatePayload {
  email: string;
  role: UserRole;
}

export interface MemberUpdatePayload {
  role?: UserRole;
  status?: MembershipStatus;
}

export interface PlatformTenant {
  id: string;
  name: string;
  slug: string;
  status: string;
  version: number;
  created_at: string;
  member_count: number;
  active_superadmin_count: number;
  package_id: string | null;
  module_overrides: Record<string, boolean> | null;
  entitlement_version: number | null;
}

export interface TenantCreatePayload {
  name: string;
  initial_superadmin_email: string;
  base_package_id: string;
}

export interface TenantUpdatePayload {
  name?: string;
  status?: 'active' | 'disabled';
  expected_version: number;
}

export interface EntitlementData {
  package_id: string;
  module_overrides: Record<string, boolean>;
  version: number;
  updated_by: string | null;
  updated_at: string | null;
}

export interface EntitlementUpdatePayload {
  package_id: string;
  module_overrides: Record<string, boolean>;
  expected_version: number;
}

export interface PendingUser {
  id: string;
  email: string;
  full_name: string | null;
  status: string;
  created_at: string;
  organization_name: string | null;
  organization_role: string | null;
}

export interface CatalogueData {
  modules: Array<{ id: string; name: string; description: string | null; status: string; created_at: string }>;
  packages: Array<{ id: string; name: string; description: string | null; is_default: boolean; version: number; created_at: string; modules: string[] }>;
}
