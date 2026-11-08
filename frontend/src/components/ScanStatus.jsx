export default function ScanStatus({ url, state, message, onRetry }) {
  if (state === 'error') {
    return (
      <div className="status error-card" role="alert">
        <strong>Scan couldn’t finish</strong>
        <p>{message}</p>
        <button onClick={onRetry}>Try again</button>
      </div>
    );
  }
  return (
    <div className="status" role="status">
      <div className="pulse" aria-hidden="true" />
      <strong>{state === 'starting' ? 'Starting investigation' : 'Investigation in progress'}</strong>
      <p className="mono">{url}</p>
    </div>
  );
}
