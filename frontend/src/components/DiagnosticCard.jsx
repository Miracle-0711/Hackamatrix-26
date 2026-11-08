const STATUS = {
  pass: { text: 'Passed', glyph: '✓' }, warn: { text: 'Needs review', glyph: '!' },
  fail: { text: 'Issue found', glyph: '✕' }, unknown: { text: 'No data', glyph: '–' },
};

export default function DiagnosticCard({ check }) {
  const s = STATUS[check.status];
  return (
    <article className="card">
      <header>
        <h3>{check.title}</h3>
        <span className="pill" data-s={check.status}><span aria-hidden="true">{s.glyph}</span> {s.text}</span>
      </header>
      {check.available ? (
        <>
          {check.findings.length > 0 && <ul>{check.findings.map((f, i) => <li key={i}>{f}</li>)}</ul>}
          {check.explanation && <p className="why">{check.explanation}</p>}
        </>
      ) : (
        <p className="why">This scan didn’t return details for this check.</p>
      )}
    </article>
  );
}
