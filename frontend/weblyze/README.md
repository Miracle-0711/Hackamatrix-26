# Weblyze: Command Center (screen 2)

    npm install
    cp .env.example .env     # set VITE_API_BASE_URL; VITE_USE_MOCK=false for the real API
    npm run dev

Flow: Intro -> Command Center (scan in progress shown inline) -> Report.
All HTTP lives in src/services/. Components never call the backend directly.

Waiting on the backend team:
- the exact `status` values (src/services/scanService.js isDone / isFailed)
- the shape of a finished result (src/pages/ReportPage.jsx currently shows raw JSON)
- a list endpoint for recent scans and a health/service-status endpoint (not invented here)
- Bouncer, Plumber and Librarian telemetry contracts
