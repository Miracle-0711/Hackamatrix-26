import { Fragment, useId, useState } from 'react';
import StatusDot from './StatusDot.jsx';

// Expandable shell shared by all three cards. Face = status + short summary + preview;
// body = technical details, revealed on click.
export default function IntelCard({ title, status, label, summary, preview, children, emptyText }) {
  const [open, setOpen] = useState(false);
  const id = useId();
  const face = (
    <>
      <span className="ititle"><span className="t">{title}</span><StatusDot status={status} label={label} /></span>
      {summary && <span className="isum">{summary}</span>}
      {preview}
    </>
  );
  if (emptyText) {
    return <article className="icard" data-s="unknown"><div className="ihead">{face}<span className="isum">{emptyText}</span></div></article>;
  }
  return (
    <article className="icard" data-s={status}>
      <h3>
        <button className="ihead" aria-expanded={open} aria-controls={id} onClick={() => setOpen((o) => !o)}>
          {face}
          <span className="ihint">{open ? 'Hide technical details' : 'Show technical details'} <span className="chev" aria-hidden="true">⌄</span></span>
        </button>
      </h3>
      <div className="ibody" id={id} data-open={open}>
        <div className="ibodyin"><div className="ibodypad">{children}</div></div>
      </div>
    </article>
  );
}

export const TechList = ({ rows }) => rows.length === 0 ? null : (
  <dl className="tech">{rows.map(([k, v]) => <Fragment key={k}><dt>{k}</dt><dd>{v}</dd></Fragment>)}</dl>
);
