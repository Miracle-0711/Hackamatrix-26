import { useState } from 'react';
import Modal from './Modal.jsx';
import { hostOf } from '../../services/threatAdapter.js';
import { submitDispute } from '../../services/threatService.js';

export default function DisputeModal({ threat, onClose, onSubmitted }) {
  const [reason, setReason] = useState('');
  const [err, setErr] = useState('');
  const [state, setState] = useState('form');          // form | saving | done

  async function submit(e) {
    e.preventDefault();
    const r = reason.trim();
    if (r.length < 10) return setErr('Explain why this report is wrong (at least 10 characters).');
    setErr(''); setState('saving');
    try { await submitDispute(threat.id, r); onSubmitted(); setState('done'); }
    catch { setErr('We couldn’t save your dispute in this browser. Please try again.'); setState('form'); }
  }

  if (state === 'done') {
    return (
      <Modal title="Dispute saved" onClose={onClose}>
        <p className="note okbox" role="status">Your dispute was saved as demo data, in this browser only. It has not been sent to a reviewer.</p>
        <div className="mactions"><button className="primary" onClick={onClose}>Done</button></div>
      </Modal>
    );
  }
  return (
    <Modal title="Dispute this report" onClose={onClose}>
      <p className="note">Demo mode: disputes are saved only in this browser and are not sent to anyone.</p>
      <p className="dim">Report for <strong className="mono">{hostOf(threat.url)}</strong>. If you believe this site was classified wrongly, tell us why.</p>
      <form onSubmit={submit} noValidate>
        <div className="fld">
          <label htmlFor="d-reason">Reason for dispute</label>
          <textarea id="d-reason" rows={4} maxLength={500} value={reason} onChange={(e) => setReason(e.target.value)} aria-invalid={!!err} />
          <span className="dim count">{reason.length}/500</span>
          {err && <span className="ferr" role="alert">{err}</span>}
        </div>
        <div className="mactions">
          <button type="button" className="ghost" onClick={onClose}>Cancel</button>
          <button type="submit" className="primary" disabled={state === 'saving'}>{state === 'saving' ? 'Saving…' : 'Submit Dispute'}</button>
        </div>
      </form>
    </Modal>
  );
}
