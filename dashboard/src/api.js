const BASE = '/admin/v1'

export async function fetchEvents(adminKey, n = 100) {
  const res = await fetch(`${BASE}/audit/tail?n=${n}`, {
    headers: { 'X-Admin-Key': adminKey },
  })
  if (!res.ok) throw new Error(`audit/tail failed: ${res.status}`)
  return res.json()
}

export function exportCSV(events) {
  const cols = ['timestamp', 'subject_id', 'tenant_id', 'resource_type', 'method', 'path', 'status_code', 'policy_result', 'risk_score', 'event_type']
  const rows = [cols.join(',')]
  for (const e of events) {
    rows.push(cols.map(c => JSON.stringify(e[c] ?? '')).join(','))
  }
  const blob = new Blob([rows.join('\n')], { type: 'text/csv' })
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = `audit-events-${new Date().toISOString().slice(0, 10)}.csv`
  a.click()
  URL.revokeObjectURL(a.href)
}
