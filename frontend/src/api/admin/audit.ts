import { apiClient } from '../client'
import type { PaginatedResponse } from '@/types'

export interface GatewayAuditIndex {
  audit_id: string
  request_id?: string
  client_request_id?: string
  user_id?: number | null
  api_key_id?: number | null
  account_id?: number | null
  group_id?: number | null
  platform?: string
  model?: string
  inbound_endpoint?: string
  upstream_endpoint?: string
  method?: string
  path?: string
  status_code?: number
  error_type?: string
  input_hash?: string
  output_hash?: string
  input_size: number
  output_size: number
  input_truncated: boolean
  output_truncated: boolean
  duration_ms: number
  time_to_first_token_ms: number
  capture_mode?: string
  sampled: boolean
  created_at: string
}

export interface GatewayAuditBodyRecord {
  sha256?: string
  size_bytes: number
  truncated: boolean
  content_type?: string
  body?: unknown
}

export interface GatewayAuditEvent {
  ts: string
  event: string
  audit_id?: string
  request_id?: string
  client_request_id?: string
  method?: string
  path?: string
  inbound_endpoint?: string
  client_ip?: string
  user_agent?: string
  user_id?: number
  api_key_id?: number
  group_id?: number
  platform?: string
  model?: string
  stream?: boolean
  account_id?: number
  account_name?: string
  account_platform?: string
  upstream_endpoint?: string
  attempts?: GatewayAuditAttempt[]
  input?: GatewayAuditBodyRecord
  output?: GatewayAuditBodyRecord
  status_code?: number
  duration_ms?: number
  time_to_first_token_ms?: number
  usage?: {
    input_tokens?: number
    output_tokens?: number
  }
  error_type?: string
  error_message?: string
}

export interface GatewayAuditAttempt {
  attempt: number
  account_id?: number
  account_name?: string
  platform?: string
  upstream_endpoint?: string
  selected_at_ms?: number
  status_code?: number
  duration_ms?: number
  error_type?: string
  error_message?: string
  result?: string
}

export interface GatewayAuditDetail {
  index: GatewayAuditIndex
  event?: GatewayAuditEvent
}

export interface GatewayAuditQueryParams {
  page?: number
  page_size?: number
  start_date?: string
  end_date?: string
  request_id?: string
  client_request_id?: string
  user_id?: number
  api_key_id?: number
  account_id?: number
  group_id?: number
  model?: string
  platform?: string
  status_code?: number
  error_type?: string
  path?: string
  inbound_endpoint?: string
  upstream_endpoint?: string
  has_input?: boolean
  has_output?: boolean
  only_errors?: boolean
}

export interface GatewayAuditStats {
  total: number
  success: number
  errors: number
  error_rate: number
  input_captured: number
  output_captured: number
  input_truncated: number
  output_truncated: number
  avg_duration_ms: number
  max_duration_ms: number
  avg_first_token_ms: number
  max_first_token_ms: number
}

export interface GatewayAuditHealth {
  indexed_total: number
  last_indexed_at?: string
  oldest_indexed_at?: string
  recent_24h: number
  errors_24h: number
  last_jsonl_file_path?: string
  last_jsonl_file_exists: boolean
  last_jsonl_file_size?: number
}

export interface GatewayAuditAccessLog {
  id: number
  operator_id: number
  audit_id: string
  action: string
  viewed_fields: string[]
  ip_address?: string
  user_agent?: string
  created_at: string
}

export async function listAudit(
  params: GatewayAuditQueryParams,
  options?: { signal?: AbortSignal }
): Promise<PaginatedResponse<GatewayAuditIndex>> {
  const { data } = await apiClient.get<PaginatedResponse<GatewayAuditIndex>>('/admin/audit', {
    params,
    signal: options?.signal
  })
  return data
}

export async function getAuditDetail(auditId: string): Promise<GatewayAuditDetail> {
  const { data } = await apiClient.get<GatewayAuditDetail>(`/admin/audit/${auditId}`)
  return data
}

export async function getAuditStats(params: GatewayAuditQueryParams): Promise<GatewayAuditStats> {
  const { data } = await apiClient.get<GatewayAuditStats>('/admin/audit/stats', { params })
  return data
}

export async function getAuditHealth(): Promise<GatewayAuditHealth> {
  const { data } = await apiClient.get<GatewayAuditHealth>('/admin/audit/health')
  return data
}

export async function listAuditAccessLogs(params?: {
  audit_id?: string
  limit?: number
}): Promise<GatewayAuditAccessLog[]> {
  const { data } = await apiClient.get<GatewayAuditAccessLog[]>('/admin/audit/access-logs', { params })
  return data
}

export async function exportAudit(params: GatewayAuditQueryParams): Promise<Blob> {
  const { data } = await apiClient.post<Blob>('/admin/audit/export', null, {
    params,
    responseType: 'blob'
  })
  return data
}

export async function getAuditByRequest(params: {
  request_id: string
  api_key_id?: number
}): Promise<GatewayAuditIndex> {
  const { data } = await apiClient.get<GatewayAuditIndex>('/admin/audit/by-request', { params })
  return data
}

export const adminAuditAPI = {
  list: listAudit,
  stats: getAuditStats,
  health: getAuditHealth,
  accessLogs: listAuditAccessLogs,
  export: exportAudit,
  getDetail: getAuditDetail,
  getByRequest: getAuditByRequest
}

export default adminAuditAPI
