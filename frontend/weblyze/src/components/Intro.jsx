import { useEffect } from 'react';

// Same animation as the approved loading intro; calls onDone at 3s.
export default function Intro({ onDone }) {
  useEffect(() => {
    const t = setTimeout(onDone, 3000);
    return () => clearTimeout(t);
  }, [onDone]);
  return (
    <div className="intro" aria-label="Weblyze" role="img">
      <div className="logo">
        <div className="dot" />
        <svg className="mark" viewBox="0 0 120 100" aria-hidden="true">
          <defs><linearGradient id="metal" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stopColor="#f4f8fc" /><stop offset=".5" stopColor="#9fb3cc" /><stop offset="1" stopColor="#e3ecf6" />
          </linearGradient></defs>
          <path pathLength="1" d="M8 10 L34 90 L60 36 L86 90 L112 10" />
        </svg>
        <div className="word" aria-hidden="true"><span className="metal">WEBLYZE</span><span className="sheen">WEBLYZE</span></div>
      </div>
    </div>
  );
}
