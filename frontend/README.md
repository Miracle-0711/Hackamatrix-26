# Weblyze (website)

React 18 + Vite. Plain CSS. No login or accounts.

## Run it (Windows, first time)
1. Install Node.js (LTS) from nodejs.org.
2. Extract this zip. Open the extracted folder, click the address bar, type `cmd`, press Enter.
3. Type `npm install` and press Enter (1-2 minutes).
4. Type `npm run dev` and press Enter, then open the link it prints (usually http://localhost:5173).
Next time you only need steps 2 and 4. Stop with Ctrl + C.

## After cloning from GitHub
`.env` is not stored on GitHub, so create it once: `copy .env.example .env` (Mac/Linux: `cp .env.example .env`),
then `npm install` and `npm run dev`.

## Screens
1. Loading intro (plays once per page load, then fades into screen 2)
2. Command Center: URL scanner, capabilities, recent investigations
3. Threat Analysis Report: score, classification, six diagnostic cards, recommendations
4. Security Intelligence: certificate chain, redirect path, headers and cookies (opens from the report)
5. Threat Intelligence Feed: filters, report a website, dispute a report
6. Scan History: every scan started from this browser

## Demo mode vs real backend
Settings live in `.env`. `VITE_USE_MOCK=true` gives clearly labelled DEMO DATA. For the real backend set
`VITE_API_BASE_URL` to its address and `VITE_USE_MOCK=false`, then restart `npm run dev`.
The agreed API is only `POST /api/scan` and `GET /api/scan/{scan_id}`. Nothing else is invented.

## Where things live
- `src/services/`: all backend access and the ONLY files that know the JSON shapes
  (`reportAdapter.js`, `intelAdapter.js`, `threatAdapter.js`). Field names there are placeholders.
- `src/services/reportAdapter.js` also holds the risk bands: Low 0-29, Medium 30-59, High Risk 60-79, Critical 80-100.
- `src/data/`: all DEMO DATA. `src/pages/`: screens. `src/components/`: reusable parts.

## Needed from the backend team
Exact `status` values, the finished-result JSON (score, classification, checks, certificate, redirects, headers, cookies),
polling vs WebSocket, CORS for the frontend address, a threat-feed API (list, report, dispute), and the
Bouncer, Plumber and Librarian telemetry contracts. Until then the threat feed and history are local/demo only.
