import { NAV_ITEMS } from '../config/navigation.js';

export default function Header({ active, onNavigate }) {
  return (
    <header className="header">
      <button className="brand" onClick={() => onNavigate('command')} aria-label="Weblyze, go to Command Center">WEBLYZE</button>
      <nav aria-label="Main">
        {NAV_ITEMS.map((n) => (
          <button key={n.id} onClick={() => onNavigate(n.id)} aria-current={active === n.id ? 'page' : undefined}>{n.label}</button>
        ))}
      </nav>
    </header>
  );
}
