import { useState } from 'react';
import Modal from './Modal.jsx';
import { CATEGORIES } from '../../services/threatAdapter.js';
import { validateUrl } from '../../services/scanService.js';
import { submitReport } from '../../services/threatService.js';

export default function ReportThreatModal({ onClose, onSubmitted }) {
  const [f, setF] = useState({ url: '', category: '', description: '' });
  const [err, setErr] = useState({});
  const [state, setState] = useState('form');          // form | saving | done
  const [fail, setFail] = useState('');
  const set = (k) => (e) => setF((s) => ({ ...s, [k]: e.target.value }));

  async function submit(e) {
    e.preventDefault();
    const errors = {}, v = validateUrl(f.url), d = f.description.trim();
    if (v.error) errors.url = v.error;
    if (!f.category) errors.category = 'Choose the type of threat.';
    if (d.length < 10) errors.description = 'Add a short description (at least 10 characters).';
    setErr(errors); setFail('');
    if (Object.keys(errors).length) return;
    setState('saving');
    try { await submitReport({ url: v.url, category: f.category, description: d }); onSubmitted(); setState('done'); }
    catch { setFail('We couldn’t save this report in your browser. Please try again.'); setState('form'); }
  }

  if (state === 'done') {
    return (
      <Modal title="Report saved" onClose={onClose}>
        <p className="note okbox" role="status">Thanks. Your report was saved as demo data, in this browser only. It has not been shared with anyone.</p>
        <div className="mactions"><button className="primary" onClick={onClose}>Done</button></div>
      </Modal>
    );
  }
  return (
    <Modal title="Report a website" onClose={onClose}>
      <p className="note">Demo mode: reports are saved only in this browser and are not shared.</p>
      <form onSubmit={submit} noValidate>
        <div className="fld">
          <label htmlFor="r-url">Website URL</label>
          <input id="r-url" value={f.url} onChange={set('url')} placeholder="https://example.com" inputMode="url" autoComplete="off" aria-invalid={!!err.url} />
          {err.url && <span className="ferr" role="alert">{err.url}</span>}
        </div>
        <div className="fld">
          <label htmlFor="r-cat">Threat category</label>
          <select id="r-cat" value={f.category} onChange={set('category')} aria-invalid={!!err.category}>
            <option value="">Select a category</option>
            {Object.entries(CATEGORIES).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
          </select>
          {err.category && <span className="ferr" role="alert">{err.category}</span>}
        </div>
        <div className="fld">
          <label htmlFor="r-desc">Short description</label>
          <textarea id="r-desc" rows={4} maxLength={300} value={f.description} onChange={set('description')} placeholder="What did the site ask for or do?" aria-invalid={!!err.description} />
          <span className="dim count">{f.description.length}/300</span>
          {err.description && <span className="ferr" role="alert">{err.description}</span>}
        </div>
        {fail && <p className="ferr" role="alert">{fail}</p>}
        <div className="mactions">
          <button type="button" className="ghost" onClick={onClose}>Cancel</button>
          <button type="submit" className="primary" disabled={state === 'saving'}>{state === 'saving' ? 'Saving…' : 'Submit Report'}</button>
        </div>
      </form>
    </Modal>
  );
}
