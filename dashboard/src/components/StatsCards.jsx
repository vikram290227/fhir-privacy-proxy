export default function StatsCards({ events }) {
  const today = new Date().toISOString().slice(0, 10)
  const todayEvents = events.filter(e => (e.timestamp || '').startsWith(today))
  const total = todayEvents.length
  const denied = todayEvents.filter(e => e.policy_result === 'deny').length
  const breakGlass = todayEvents.filter(e => e.event_type === 'break_glass').length

  return (
    <div style={{ display: 'flex', gap: 16, marginBottom: 20, flexWrap: 'wrap' }}>
      <Card label="Total Events Today" value={total} color="#2563eb" />
      <Card label="Denied Today" value={denied} color="#dc2626" />
      <Card label="Break-Glass Today" value={breakGlass} color="#d97706" />
      <Card label="All Events Loaded" value={events.length} color="#6b7280" />
    </div>
  )
}

function Card({ label, value, color }) {
  return (
    <div style={{
      background: '#fff',
      border: `2px solid ${color}`,
      borderRadius: 10,
      padding: '16px 24px',
      minWidth: 160,
      flex: 1,
    }}>
      <div style={{ fontSize: 32, fontWeight: 700, color }}>{value}</div>
      <div style={{ fontSize: 13, color: '#6b7280', marginTop: 4 }}>{label}</div>
    </div>
  )
}
