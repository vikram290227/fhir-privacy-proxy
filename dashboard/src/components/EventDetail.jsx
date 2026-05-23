export default function EventDetail({ event, onClose }) {
  return (
    <div style={{
      position: 'fixed', inset: 0, background: 'rgba(0,0,0,.45)',
      display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 100,
    }} onClick={onClose}>
      <div
        onClick={e => e.stopPropagation()}
        style={{
          background: '#fff', borderRadius: 12, padding: 24, maxWidth: 720, width: '90%',
          maxHeight: '80vh', overflow: 'auto', boxShadow: '0 20px 60px rgba(0,0,0,.3)',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
          <h2 style={{ fontSize: 16, fontWeight: 700 }}>Event Detail</h2>
          <button onClick={onClose} style={{ background: 'none', border: 'none', fontSize: 20, cursor: 'pointer', color: '#6b7280' }}>✕</button>
        </div>
        {event.break_glass && (
          <div style={{ background: '#fef2f2', border: '1px solid #ef4444', borderRadius: 8, padding: 12, marginBottom: 16, fontSize: 13 }}>
            <strong style={{ color: '#dc2626' }}>Break-Glass:</strong> {event.break_glass.justification}
            {event.break_glass.requested_by && <span> — requested by {event.break_glass.requested_by}</span>}
          </div>
        )}
        <pre style={{
          background: '#f8fafc', border: '1px solid #e2e8f0', borderRadius: 8,
          padding: 16, fontSize: 12, overflow: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-all',
        }}>
          {JSON.stringify(event, null, 2)}
        </pre>
      </div>
    </div>
  )
}
