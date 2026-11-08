import { useRef, useState } from 'react';
import { validateUrl } from '../services/scanService.js';

export default function URLScanner({ onSubmit, disabled }) {
  const [value, setValue] = useState('');
  const [error, setError] = useState('');
  const input = useRef();

  function submit(e) {
    e.preventDefault();
    const res = validateUrl(value);
    if (res.error) return setError(res.error);
    setError('');
    onSubmit(res.url);
  }

  async function paste() {
    try {
      const text = await navigator.clipboard.readText();
      setValue(text.trim()); setError(''); input.current?.focus();
    } catch {
      setError('Clipboard access was blocked. Click the field and press Ctrl+V (Cmd+V on Mac) instead.');
    }
  }

  return (
    <form className="scanner" onSubmit={submit} noValidate>
      <div className={'field' + (error ? ' invalid' : '')}>
        <input ref={input} value={value} onChange={(e) => setValue(e.target.value)} disabled={disabled}
          placeholder="Paste a website address, e.g. example.com" aria-label="Website URL"
          aria-invalid={!!error} aria-describedby="url-error" autoComplete="off" inputMode="url" />
        <button type="button" className="ghost" onClick={paste} disabled={disabled}>Paste URL</button>
        <button type="submit" disabled={disabled}>Scan Website</button>
      </div>
      <p id="url-error" className="error" role="alert">{error}</p>
    </form>
  );
}
