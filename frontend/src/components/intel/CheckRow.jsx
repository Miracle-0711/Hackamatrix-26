import { useId, useState } from 'react';
import StatusDot, { CHECK_LABEL } from './StatusDot.jsx';
import { explain } from '../../data/checkInfo.js';

// One security check (a header or a cookie setting) that expands to explain what it means.
export default function CheckRow({ check }) {
  const [open, setOpen] = useState(false);
  const id = useId();
  return (
    <li className="chk">
      <button className="chkhead" aria-expanded={open} aria-controls={id} onClick={() => setOpen((o) => !o)}>
        <span className="chkname">{check.name}</span>
        <StatusDot status={check.status} label={CHECK_LABEL[check.status]} />
        <span className="chev" aria-hidden="true">⌄</span>
      </button>
      <div className="chkbody" id={id} data-open={open}>
        <div className="ibodyin"><div className="chkpad">
          {check.note && <p><b>Result</b>{check.note}</p>}
          <p><b>What it means</b>{explain(check.name) ?? 'No explanation is available for this check yet.'}</p>
        </div></div>
      </div>
    </li>
  );
}
