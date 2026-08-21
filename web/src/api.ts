// Typed API client. Every state-changing request carries the CSRF token
// read from the double-submit cookie; the session rides in an HttpOnly
// cookie the script cannot touch.

export interface User {
  id: string
  username: string
  role: 'user' | 'admin'
}

export interface FileNode {
  id: string
  name: string
  mimeType: string
  size: number
  owner: string
  myRole: 'owner' | 'editor' | 'viewer'
  createdAt: string
  updatedAt: string
}

export interface ShareGrant {
  username: string
  role: 'editor' | 'viewer'
}

// What the sign-up form may learn about the registration policy.
export interface RegistrationStatus {
  mode: 'open' | 'invite' | 'closed'
  acceptingRegistrations: boolean
  inviteRequired: boolean
}

// An issued invite as listed to admins; the code itself is shown once at
// creation and never again.
export interface Invite {
  id: string
  note: string
  createdBy: string
  createdAt: string
  expiresAt: string
  usedBy: string
  usedAt: string | null
  revokedAt: string | null
  status: 'active' | 'used' | 'revoked' | 'expired'
}

export interface AuditEvent {
  id: number
  at: string
  actor: string
  action: string
  target: string
  result: string
  reason: string
  requestId: string
}

export class ApiError extends Error {
  status: number
  constructor(status: number, message: string) {
    super(message)
    this.status = status
  }
}

function csrfToken(): string {
  const match = document.cookie.match(/(?:^|;\s*)sv_csrf=([^;]*)/)
  return match ? decodeURIComponent(match[1]) : ''
}

async function request<T>(method: string, path: string, body?: unknown): Promise<T> {
  const headers: Record<string, string> = {}
  if (method !== 'GET') headers['X-CSRF-Token'] = csrfToken()
  if (body !== undefined) headers['Content-Type'] = 'application/json'

  const resp = await fetch(path, {
    method,
    headers,
    body: body !== undefined ? JSON.stringify(body) : undefined,
  })
  const data = await resp.json().catch(() => ({}))
  if (!resp.ok) {
    throw new ApiError(resp.status, (data as { error?: string }).error ?? 'request failed')
  }
  return data as T
}

export const api = {
  me: () => request<User>('GET', '/api/auth/me'),
  registrationStatus: () => request<RegistrationStatus>('GET', '/api/auth/registration'),
  register: (username: string, password: string, inviteCode?: string) =>
    request<User>(
      'POST',
      '/api/auth/register',
      inviteCode ? { username, password, inviteCode } : { username, password },
    ),
  login: (username: string, password: string) =>
    request<User>('POST', '/api/auth/login', { username, password }),
  logout: () => request<{ status: string }>('POST', '/api/auth/logout'),
  changePassword: (currentPassword: string, newPassword: string) =>
    request<{ status: string }>('POST', '/api/auth/password', { currentPassword, newPassword }),

  listFiles: () => request<{ files: FileNode[] }>('GET', '/api/files'),
  statFile: (id: string) =>
    request<{ file: FileNode; shares?: ShareGrant[] }>('GET', `/api/files/${id}`),
  rename: (id: string, name: string) => request<FileNode>('PATCH', `/api/files/${id}`, { name }),
  remove: (id: string) => request<{ status: string }>('DELETE', `/api/files/${id}`),
  share: (id: string, username: string, role: string) =>
    request<{ status: string }>('PUT', `/api/files/${id}/shares`, { username, role }),
  revoke: (id: string, username: string) =>
    request<{ status: string }>('DELETE', `/api/files/${id}/shares/${encodeURIComponent(username)}`),

  adminUsers: () =>
    request<{ users: { id: string; username: string; role: string; createdAt: string }[] }>(
      'GET',
      '/api/admin/users',
    ),
  // Keyset paging: pass the previous page's nextBefore to get older events.
  adminAudit: (limit: number, before?: number | null) =>
    request<{ events: AuditEvent[]; nextBefore: number | null }>(
      'GET',
      `/api/admin/audit?limit=${limit}${before ? `&before=${before}` : ''}`,
    ),
  adminInvites: () => request<{ invites: Invite[] }>('GET', '/api/admin/invites'),
  adminCreateInvite: (note: string, ttlHours: number) =>
    request<{ code: string; invite: Invite }>('POST', '/api/admin/invites', { note, ttlHours }),
  adminRevokeInvite: (id: string) =>
    request<{ status: string }>('DELETE', `/api/admin/invites/${id}`),
}

// upload uses XHR for real progress events; fetch cannot report them.
export function uploadFile(file: File, onProgress: (percent: number) => void): Promise<FileNode> {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest()
    xhr.open('POST', '/api/files')
    xhr.setRequestHeader('X-CSRF-Token', csrfToken())
    xhr.upload.onprogress = (e) => {
      if (e.lengthComputable) onProgress(Math.round((e.loaded / e.total) * 100))
    }
    xhr.onload = () => {
      let data: unknown = {}
      try {
        data = JSON.parse(xhr.responseText)
      } catch {
        /* controlled error below */
      }
      if (xhr.status >= 200 && xhr.status < 300) {
        resolve(data as FileNode)
      } else {
        reject(new ApiError(xhr.status, (data as { error?: string }).error ?? 'upload failed'))
      }
    }
    xhr.onerror = () => reject(new ApiError(0, 'network error'))
    const form = new FormData()
    form.append('file', file)
    xhr.send(form)
  })
}

export function downloadUrl(id: string): string {
  return `/api/files/${id}/download`
}
