export const CHECK_LABEL = { pass: 'Passed', warn: 'Warning', fail: 'Failed', unknown: 'No data' };

export default function StatusDot({ status, label }) {
  return <span className="sdot" data-s={status}><i aria-hidden="true" />{label}</span>;
}
