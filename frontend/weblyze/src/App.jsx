import { useState } from 'react';
import Intro from './components/Intro.jsx';
import CommandCenter from './pages/CommandCenter.jsx';
import ReportPage from './pages/ReportPage.jsx';

// Flow: intro -> command (scan in progress is shown inside it) -> report
export default function App() {
  const [view, setView] = useState('intro');
  const [report, setReport] = useState(null);
  return (
    <div className="stage">
      {view === 'intro' && <Intro onDone={() => setView('command')} />}
      {view === 'command' && <div className="fade-in"><CommandCenter onComplete={(d) => { setReport(d); setView('report'); }} /></div>}
      {view === 'report' && <div className="fade-in"><ReportPage data={report} onBack={() => setView('command')} /></div>}
    </div>
  );
}
