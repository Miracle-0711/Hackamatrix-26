// Placeholder for the Threat Analysis Report screen. Shows the backend response as-is.
export default function ReportPage({ data, onBack }) {
  return (
    <div className="center"><main className="report">
      <button className="back" onClick={onBack}>Back to Command Center</button>
      <h1>Threat Analysis Report</h1>
      <p className="mono">{data.url}</p>
      {data.result._mock && <div className="mock">Mock data. Not a real analysis.</div>}
      <pre>{JSON.stringify(data.result, null, 2)}</pre>
    </main></div>
  );
}
