import api, { ApiResponse, PaginationParams, PaginatedResponse } from '@/lib/api'

export interface Asset {
  id: string
  name: string
  type: 'ip' | 'domain' | 'web' | 'app'
  target: string
  status: string
  tags: string[]
  groupId?: string
  ipInfo?: IPInfo
  domainInfo?: DomainInfo
  webInfo?: WebInfo
  appInfo?: APPInfo
  lastScanTime?: string
  createdAt: string
  updatedAt: string
}

export interface IPInfo {
  ip: string
  ports: number[]
  services: ServiceInfo[]
  os?: string
  location?: string
  isp?: string
}

export interface ServiceInfo {
  port: number
  protocol: string
  service: string
  version?: string
  banner?: string
}

export interface DomainInfo {
  domain: string
  subdomains: string[]
  resolveIPs: string[]
  whois?: string
  dns?: Record<string, string[]>
}

export interface WebInfo {
  url: string
  title?: string
  statusCode?: number
  server?: string
  technologies: string[]
  fingerprints: string[]
}

export interface APPInfo {
  name: string
  packageName?: string
  version?: string
  platform?: string
  apis?: string[]
}

// Helper function to transform backend asset to frontend asset
const transformAsset = (backendAsset: Record<string, unknown>): Asset => ({
  ...backendAsset,
  id: backendAsset.id as string,
  name: (backendAsset.title as string) || '',
  target: (backendAsset.value as string) || '',
  type: backendAsset.type as Asset['type'],
  status: String(backendAsset.status || 'active'),
  tags: (backendAsset.tags as string[]) || [],
  groupId: backendAsset.group_id as string,
  lastScanTime: backendAsset.last_scan_time as string,
  createdAt: backendAsset.created_at as string,
  updatedAt: backendAsset.updated_at as string,
} as Asset)

export interface AssetGroup {
  id: string
  name: string
  description?: string
  assetCount: number
  createdAt: string
}

// Backend paginated response format
interface BackendPaginatedResponse {
  code: number
  message: string
  data: unknown[]
  total: number
  page: number
  size: number
}

export const assetApi = {
  // Assets
  getAssets: async (params?: PaginationParams & {
    type?: string
    status?: string
    groupId?: string
    tags?: string[]
  }): Promise<PaginatedResponse<Asset>> => {
    // Transform params: frontend uses pageSize, backend uses page_size
    const backendParams = {
      page: params?.page,
      page_size: params?.pageSize,
      keyword: params?.search,
      type: params?.type,
      group_id: params?.groupId,
      tags: params?.tags?.join(','),
    }
    const response: BackendPaginatedResponse = await api.get('/assets', { params: backendParams })
    // Backend returns: { code, message, data: [...], total, page, size }
    // Frontend expects: { code, message, data: { list: [...], total, page, pageSize } }
    const transformedResponse: PaginatedResponse<Asset> = {
      code: response.code,
      message: response.message,
      data: {
        list: (response.data || []).map((item: unknown) => transformAsset(item as Record<string, unknown>)),
        total: response.total || 0,
        page: response.page || 1,
        pageSize: response.size || 10,
      }
    }
    return transformedResponse
  },

  getAsset: async (id: string): Promise<ApiResponse<Asset>> => {
    const response: ApiResponse<Asset> = await api.get(`/assets/${id}`)
    if (response.data) {
      response.data = transformAsset(response.data as unknown as Record<string, unknown>)
    }
    return response
  },

  createAsset: async (data: Partial<Asset>): Promise<ApiResponse<Asset>> => {
    // Map frontend field names to backend expected field names
    const payload = {
      type: data.type,
      value: data.target, // backend expects 'value', frontend uses 'target'
      title: data.name,   // backend expects 'title', frontend uses 'name'
      tags: data.tags,
      group_id: data.groupId,
    }
    const response: ApiResponse<Asset> = await api.post('/assets', payload)
    if (response.data) {
      response.data = transformAsset(response.data as unknown as Record<string, unknown>)
    }
    return response
  },

  updateAsset: async (id: string, data: Partial<Asset>): Promise<ApiResponse<Asset>> => {
    const payload = {
      type: data.type,
      value: data.target,
      title: data.name,
      tags: data.tags,
      group_id: data.groupId,
    }
    const response: ApiResponse<Asset> = await api.put(`/assets/${id}`, payload)
    if (response.data) {
      response.data = transformAsset(response.data as unknown as Record<string, unknown>)
    }
    return response
  },

  deleteAsset: (id: string): Promise<ApiResponse<null>> =>
    api.delete(`/assets/${id}`),

  batchDeleteAssets: (ids: string[]): Promise<ApiResponse<null>> =>
    api.post('/assets/batch-delete', { ids }),

  importAssets: (file: File): Promise<ApiResponse<{ imported: number; failed: number }>> => {
    const formData = new FormData()
    formData.append('file', file)
    return api.post('/assets/import', formData, {
      headers: { 'Content-Type': 'multipart/form-data' }
    })
  },

  exportAssets: (params?: { type?: string; groupId?: string }): Promise<Blob> =>
    api.get('/assets/export', { params, responseType: 'blob' }),

  // Asset Groups
  getGroups: (params?: PaginationParams): Promise<PaginatedResponse<AssetGroup>> =>
    api.get('/asset-groups', { params }),

  createGroup: (data: { name: string; description?: string }): Promise<ApiResponse<AssetGroup>> =>
    api.post('/asset-groups', data),

  updateGroup: (id: string, data: { name?: string; description?: string }): Promise<ApiResponse<AssetGroup>> =>
    api.put(`/asset-groups/${id}`, data),

  deleteGroup: (id: string): Promise<ApiResponse<null>> =>
    api.delete(`/asset-groups/${id}`),

  moveAssetsToGroup: (assetIds: string[], groupId: string): Promise<ApiResponse<null>> =>
    api.post('/asset-groups/move', { assetIds, groupId }),
}
