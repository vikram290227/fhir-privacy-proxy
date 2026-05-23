import { useState, useEffect, useCallback } from 'react'
import { fetchEvents, exportCSV } from './api.js'
import StatsCards from './components/StatsCards.jsx'
import BreakGlassAlert from './components/BreakGlassAlert.jsx'
import EventTable from './components/EventTable.jsx'
import EventDetail from './components/EventDetail.jsx'

const REFRESH_MS = 30_000

export default function App() {
  const [adminKey, setAdminKey] = useState(localStorage.getItem('adminKey') || '')
  const [events, setEvents] = useState([])
  const [error, setError] = useState(null)
  const [loading, setLoading] = useState(false)
  const [selected, setSelected] = useState(null)
  const [filters, setFilters] = useState({ tenant: '', decision: '', severity: '' })

  const load = useCallback(async () => {
    if (!adminKey) return
    setLoading(true)
    try {
      const data = await fetchEvents(adminKey)
      setEvents(Array.isArray(data) ? data : data.events ?? [])
      setError(null)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [adminKey])

  useEffect(() => {
    load()
    const id = setInterval(load, REFRESH_MS)
    return () => clearInterval(id)
  }, [load])

  const filtered = events.filter(e => {
    if (filters.tenant && e.tenant_id !== filters.tenant) return false
    if (filters.decision && e.policy_result !== filters.decision) return false
    if (filters.severity === 'critical' && e.event_type !== 'break_glass') return false
    return true
  })

  const breakGlass = events.filter(e => e.event_type === 'break_glass')
  const tenants = [...new Set(events.map(e => e.tenant_id).filter(Boolean))]

  function saveKey(k) {
    setAdminKey(k)
    localStorage.setItem('adminKey', k)
  }

  return (
    <div style={{ minHeight: '100vh', padding: '24px', maxWidth: 1400, margin: '0 auto' }}>
      <header style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 24 }}>
        <h1 style={{ fontSize: 22, fontWeight: 700, flex: 1 }}>FHIR Privacy Officer Dashboard</h1>
        <input
          type="password"
          placeholder="Admin API Key"
          value={adminKey}
          onChange={e => saveKey(e.target.value)}
          style={{ padding: '6px 10px', border: '1px solid #ccc', borderRadius: 6, width: 220 }}
        />
        <button onClick={load} disabled={loading} style={btnStyle}>
          {loading ? 'Loading…' : 'Refresh'}
        </button>
        <button onClick={() => exportCSV(filtered)} style={{ ...btnStyle, background: '#16a34a' }}>
          Export CSV
        </button>
      </header>

      {error && (
        <div style={{ background: '#fee2e2', border: '1px solid #f87171', borderRadius: 8, padding: 12, marginBottom: 16, color: '#991b1b' }}>
          {error}
        </div>
      )}

      <StatsCards events={events} />

      {breakGlass.length > 0 && <BreakGlassAlert events={breakGlass} onSelect={setSelected} />}

      <div style={{ display: 'flex', gap: 12, margin: '16px 0', flexWrap: 'wrap' }}>
        <select value={filters.tenant} onChange={e => setFilters(f => ({ ...f, tenant: e.target.value }))} style={selectStyle}>
          <option value="">All Tenants</option>
          {tenants.map(t => <option key={t} value={t}>{t}</option>)}
        </select>
        <select value={filters.decision} onChange={e => setFilters(f => ({ ...f, decision: e.target.value }))} style={selectStyle}>
          <option value="">All Decisions</option>
          <option value="allow">Allow</option>
          <option value="deny">Deny</option>
        </select>
        <select value={filters.severity} onChange={e => setFilters(f => ({ ...f, severity: e.target.value }))} style={selectStyle}>
          <option value="">All Severity</option>
          <option value="critical">Critical (Break-Glass)</option>
        </select>
      </div>

      <EventTable events={filtered} onSelect={setSelected} selected={selected} />

      {selected && <EventDetail event={selected} onClose={() => setSelected(null)} />}
    </div>
  )
}

const btnStyle = {
  padding: '6px 14px',
  background: '#2563eb',
  color: '#fff',
  border: 'none',
  borderRadius: 6,
  cursor: 'pointer',
  fontWeight: 600,
}

const selectStyle = {
  padding: '6px 10px',
  border: '1px solid #d1d5db',
  borderRadius: 6,
  background: '#fff',
}
