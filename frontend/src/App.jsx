import { useEffect, useState } from 'react';
import Intro from './components/Intro.jsx';
import Header from './components/Header.jsx';
import CommandCenter from './pages/CommandCenter.jsx';
import HistoryPage from './pages/HistoryPage.jsx';
import ReportPage from './pages/ReportPage.jsx';
import IntelligencePage from './pages/IntelligencePage.jsx';
import ThreatFeedPage from './pages/ThreatFeedPage.jsx';

const TITLES = { command: 'Command Center', history: 'Scan History', intel: 'Threat Intelligence', report: 'Threat Analysis Report', intelligence: 'Security Intelligence' };

// Flow: intro -> command (scan in progress shows inside it) -> report.
// view ids match config/navigation.js; 'report' is reached from a scan or a history row,
// and 'intelligence' from the report.
export default function App() {
  const [view, setView] = useState('intro');
  const [introVisible, setIntroVisible] = useState(true);
  const [report, setReport] = useState(null);
  const openReport = (data) => { setReport(data); setView('report'); };
  useEffect(() => { document.title = view === 'intro' ? 'Weblyze' : `${TITLES[view]} · Weblyze`; window.scrollTo(0, 0); }, [view]);

  return (
    <div className="stage">
      {view !== 'intro' && (
        <div className="center fade-in">
          <Header active={view === 'report' || view === 'intelligence' ? 'command' : view} onNavigate={setView} />
          {view === 'command' && <CommandCenter onReport={openReport} onNavigate={setView} />}
          {view === 'history' && <HistoryPage onReport={openReport} />}
          {view === 'intel' && <ThreatFeedPage />}
          {view === 'report' && <ReportPage data={report} onBack={() => setView('command')} onIntelligence={() => setView('intelligence')} />}
          {view === 'intelligence' && <IntelligencePage data={report} onBack={() => setView('report')} />}
        </div>
      )}
      {introVisible && <Intro onDone={() => setView('command')} onGone={() => setIntroVisible(false)} />}
    </div>
  );
}
