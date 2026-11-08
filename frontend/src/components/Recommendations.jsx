export default function Recommendations({ items }) {
  return (
    <section aria-labelledby="rec-h">
      <h2 id="rec-h" className="section">Recommendations</h2>
      {items.length === 0 ? (
        <p className="empty">No recommendations were provided for this scan.</p>
      ) : (
        <ol className="recs">
          {items.map((r, i) => (
            <li key={i}>
              {r.risk && <strong>{r.risk}</strong>}
              {r.action && <span>{r.action}</span>}
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}
