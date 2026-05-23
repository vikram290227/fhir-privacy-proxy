export default function BreakGlassAlert({ events, onSelect }) {
  return (
    <div style={{ background: '#fef2f2', border: '2px solid #ef4444', borderRadius: 10, padding: 16, marginBottom: 16 }}>
      <div style={{ fontWeight: 700, color: '#dc2626', marginBottom: 10, fontSize: 15 }}>
        CRITICAL: {events.length} Break-Glass Event{events.length !== 1 ? 's' : ''}
      </div>
      {events.slice(0, 5).map((e, i) => (
        <div
          key={i}
          onClick={() => onSelect(e)}
          style={{ cursor: 'pointer', padding: '6px 8px', borderRadius: 6, marginBottom: 4, background: '#fee2e2', fontSize: 13 }}
        >
          <strong>{e.subject_id}</strong> — {e.timestamp} — {e.break_glass?.justification ?? 'no justification'}
        </div>
      ))}
      {events.length > 5 && (
        <div style={{ fontSize: 12, color: '#9ca3af', marginTop: 4 }}>+{events.length - 5} more — use filter to view all</div>
      )}
    </div>
  )
}
