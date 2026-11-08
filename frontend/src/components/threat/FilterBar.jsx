export default function FilterBar({ filters, value, onChange }) {
  return (
    <div className="tf-filters" role="group" aria-label="Filter threats">
      {filters.map((f) => (
        <button key={f.id} aria-pressed={value === f.id} onClick={() => onChange(f.id)}>{f.label}</button>
      ))}
    </div>
  );
}
