/** Explicit credentials stay scoped to this origin and browser tab, not cookies. */
const storageKey = 'void-local-access-token'
const fragment = new URLSearchParams(window.location.hash.slice(1))
const incoming = fragment.get('access_token')
if (incoming) {
  // Clear before any API request or third-party browser interaction.
  window.history.replaceState(null, '', window.location.pathname + window.location.search)
  if (/^[0-9a-f]{64}$/.test(incoming)) sessionStorage.setItem(storageKey, incoming)
}

export function sessionToken(): string {
  return sessionStorage.getItem(storageKey) ?? ''
}

export function sessionHeaders(): Record<string, string> {
  return { Authorization: `Bearer ${sessionToken()}` }
}
