import { useState } from 'react'

const PAGE_SIZE = 20

export default function EventTable({ events, onSelect, selected }) {
  const [page, setPage] = useState(0)
  const totalPages = Math.ceil(events.length / PAGE_SIZE)
  const slice = events.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE)

  return (
    <div style={{ background: '#fff', borderRadius: 10, overflow: 'hidden', boxShadow: '0 1px 3px rgba(0,0,0,.1)' }}>
      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 13 }}>
        <thead>
          <tr style={{ background: '#f1f5f9' }}>
            {['Timestamp', 'User', 'Tenant', 'Resource', 'Method', 'Decision', 'Risk'].map(h => (
              <th key={h} style={thStyle}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {slice.length === 0 && (
            <tr><td colSpan={7} style={{ textAlign: 'center', padding: 24, color: '#9ca3af' }}>No events</td></tr>
          )}
          {slice.map((e, i) => {
            const isBG = e.event_type === 'break_glass'
            const isDeny = e.policy_result === 'deny'
            const isSelected = selected === e
            return (
              <tr
                key={i}
                onClick={() => onSelect(e)}
                style={{
                  cursor: 'pointer',
                  background: isSelected ? '#dbeafe' : isBG ? '#fef2f2' : isDeny ? '#fff7ed' : 'transparent',
                  borderBottom: '1px solid #f1f5f9',
                }}
              >
                <td style={tdStyle}>{(e.timestamp || '').replace('T', ' ').slice(0, 19)}</td>
                <td style={tdStyle}>{e.subject_id}</td>
                <td style={tdStyle}>{e.tenant_id}</td>
                <td style={tdStyle}>{e.resource_type}</td>
                <td style={tdStyle}>{e.method}</td>
                <td style={tdStyle}>
                  <span style={{
                    padding: '2px 8px', borderRadius: 99, fontSize: 11, fontWeight: 700,
                    background: isBG ? '#ef4444' : isDeny ? '#f97316' : '#22c55e',
                    color: '#fff',
                  }}>
                    {isBG ? 'BREAK-GLASS' : e.policy_result?.toUpperCase()}
                  </span>
                </td>
                <td style={tdStyle}>{e.risk_score != null ? e.risk_score.toFixed(2) : '—'}</td>
              </tr>
            )
          })}
        </tbody>
      </table>
      {totalPages > 1 && (
        <div style={{ display: 'flex', gap: 8, justifyContent: 'center', padding: 12 }}>
          <button onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0} style={pgBtn}>Prev</button>
          <span style={{ alignSelf: 'center', fontSize: 13, color: '#6b7280' }}>Page {page + 1} / {totalPages}</span>
          <button onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))} disabled={page === totalPages - 1} style={pgBtn}>Next</button>
        </div>
      )}
    </div>
  )
}

const thStyle = { padding: '10px 12px', textAlign: 'left', fontWeight: 600, fontSize: 12, color: '#374151', whiteSpace: 'nowrap' }
const tdStyle = { padding: '8px 12px', whiteSpace: 'nowrap', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis' }
const pgBtn = { padding: '4px 12px', border: '1px solid #d1d5db', borderRadius: 6, cursor: 'pointer', background: '#fff' }
