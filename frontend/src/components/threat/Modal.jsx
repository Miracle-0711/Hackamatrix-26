import { useEffect, useId, useRef } from 'react';

// Accessible dialog: Esc and backdrop close, focus moves in, Tab stays inside, focus returns on close.
export default function Modal({ title, onClose, children }) {
  const ref = useRef();
  const closeRef = useRef(onClose);
  closeRef.current = onClose;
  const id = useId();
  useEffect(() => {
    const prev = document.activeElement, el = ref.current;
    const sel = 'a[href],button:not([disabled]),input,select,textarea';
    (el.querySelector('input,select,textarea') || el).focus();
    const onKey = (e) => {
      if (e.key === 'Escape') closeRef.current();
      if (e.key !== 'Tab') return;
      const f = [...el.querySelectorAll(sel)];
      if (!f.length) return;
      const a = f[0], z = f[f.length - 1];
      if (e.shiftKey && document.activeElement === a) { e.preventDefault(); z.focus(); }
      else if (!e.shiftKey && document.activeElement === z) { e.preventDefault(); a.focus(); }
    };
    document.addEventListener('keydown', onKey);
    const overflow = document.body.style.overflow;
    document.body.style.overflow = 'hidden';
    return () => { document.removeEventListener('keydown', onKey); document.body.style.overflow = overflow; prev?.focus?.(); };
  }, []);
  return (
    <div className="mback" onMouseDown={(e) => e.target === e.currentTarget && onClose()}>
      <div className="modal" role="dialog" aria-modal="true" aria-labelledby={id} tabIndex={-1} ref={ref}>
        <header><h2 id={id}>{title}</h2><button className="x" aria-label="Close" onClick={onClose}>✕</button></header>
        {children}
      </div>
    </div>
  );
}
