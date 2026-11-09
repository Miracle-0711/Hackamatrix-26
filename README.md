# Hackamatrix-26

01 Project name and one-line description
Weblyze: paste a link, get a clear risk score and plain-language explanation of whether a website can be trusted, before you click, log in or pay.

02 Problem
This project answers the problem statement AI-Powered Web Threat Detection & Digital Trust Intelligence: build an intelligent platform that detects phishing and malicious websites by combining threat analysis, web security assessment, certificate validation and collaborative threat intelligence.


Daily life now runs through websites: banking, education, recruitment, e-commerce, payments and business communication. That makes individuals and organisations easy targets. The problem statement lists phishing websites, fraudulent payment links, fake recruitment portals, impersonated organisations, malicious redirects, deceptive advertisements and credential-harvesting attacks, all becoming more sophisticated. A fraudulent site can closely copy a bank, a university, a government service or a company, so users unknowingly hand over passwords, financial information and personal details.


The problem goes deeper than fake pages. The statement also points to weaknesses in the internet's trust infrastructure: weak cryptography, compromised certificate authorities and badly managed certificate chains can undermine HTTPS and website identity checks. It cites the recent eMudhra TLS certificate incident as an example of how flaws in certificate authority key generation could allow fraudulent certificates to be used for impersonation, and stresses the need for certificate transparency, cryptographic validation and continuous monitoring. At the application level, insecure configurations, exposed services and outdated software add further risk.


Finally, existing security tools tend to tackle these problems separately. There is no accessible platform that brings intelligent threat detection, website security analysis, certificate validation and collaborative threat intelligence together, and the results are rarely explained in a way everyday users can act on.

03 Solution
Weblyze is that platform. We are the frontend team: this repository is the user-facing layer, which lets anyone investigate a website and understand the result. Detection and analysis run in the Weblyze backend (built by our teammates as Bouncer, Plumber and Librarian, coordinated by an orchestrator), and the frontend presents what the backend reports in plain language. A user pastes a URL and gets a 0-100 risk score with a classification: Low 0-29 (green), Medium 30-59 (yellow), High Risk 60-79 (orange), Critical 80-100 (red).


How each part of the problem statement shows up in the interface:


Problem statement pillar
	What the frontend provides
	Threat analysis
	Command Center scanner and the Threat Analysis Report: score, classification, six diagnostic cards (threat detection, domain intelligence, SSL/TLS, brand impersonation, redirects, website security) and recommended actions
	Web security assessment
	Security Intelligence view: HTTP security header checks and cookie checks (Secure, HttpOnly, SameSite) with Passed, Warning and Failed indicators that expand to explain what each means
	Certificate validation
	A visual Root → Intermediate → Leaf certificate chain with issuer, issue and expiry dates, and clear highlighting of invalid, expired, missing or suspicious certificates. Also the full redirect path with status codes and flagged domain changes
	Collaborative threat intelligence
	Threat Intelligence Feed: community-reported sites with category, risk and verification status, filters, a "Report a Website" form, and a false-positive dispute flow for verified reports
	

Also included: Scan History, and a companion Chrome extension (Manifest V3, separate project) that shows a site's risk in a popup and a warning overlay on dangerous sites. There is no login or account creation.


Current status: the frontend is complete and runs in a clearly labelled demo mode (sample data marked DEMO DATA). It is built against the agreed backend contract (POST /api/scan, GET /api/scan/{scan_id}) and switches to the real backend with two lines in .env. The threat feed and scan history are stored locally in the browser until the backend provides APIs for them.

04 Demo links and a screenshot
* Live demo: https://webai23.netlify.app

05 Tech stack
Area
	What we used
	Language
	JavaScript (ES modules) with JSX
	UI library
	React 18
	Build tool and dev server
	Vite 5 with @vitejs/plugin-react
	HTTP client
	Axios
	Styling
	Plain CSS written for this project (custom properties, grid, flexbox, keyframe animations). No CSS framework
	Font
	Jost (Google Fonts)
	State and storage
	React hooks; browser localStorage for scan history and local threat reports
	Package manager
	npm
	Backend 
  python
	
	06 Architecture
flowchart LR
  U["User in browser"] --> UI["React screens<br/>src/pages and src/components"]
  UI --> SV["Service layer<br/>src/services"]
  SV -->|"VITE_USE_MOCK=true"| D["Labelled DEMO DATA<br/>src/data"]
  SV -->|"POST /api/scan<br/>GET /api/scan/:id"| B["Backend orchestrator"]
  B --- BO["Bouncer"]
  B --- PL["Plumber"]
  B --- LI["Librarian"]

Flow: Loading intro → Command Center → scan in progress → Threat Analysis Report → Security Intelligence. Threat Intelligence Feed and Scan History are reachable from the header.


Key decisions


* UI never talks to the backend directly. All HTTP is in src/services/ (Axios instance in api.js, scan logic in scanService.js). The backend address comes only from VITE_API_BASE_URL.
* One adapter per data shape. reportAdapter.js, intelAdapter.js and threatAdapter.js are the only files that know the backend's JSON field names (currently placeholders). When the backend contract is confirmed, only those files change.
* No fabricated results. Anything the backend does not return shows as "No data" or "Not provided". Sample content lives only in src/data/ and is always labelled DEMO DATA.
* One source of truth for risk levels. The score bands are defined once in reportAdapter.js and every screen derives its classification and colour from the score.
* Polling now, WebSocket later. Scan status updates sit behind a single watchScan function.


src/
  App.jsx                 screen routing, page titles
  pages/                  CommandCenter, ReportPage, IntelligencePage, ThreatFeedPage, HistoryPage
  components/             Header, URLScanner, ScanStatus, Intro, report/ intel/ threat/ parts
  services/               api.js, scanService.js, *Adapter.js, threatService.js
  data/                   demo reports, intelligence, threats, check explanations
  config/navigation.js    header navigation
07 Setup and run steps
Requirements: Node.js 18 or newer (LTS) and Git.


git clone https://github.com/Miracle-0711/Hackamatrix-26
cd <REPOSITORY-FOLDER>
npm install
cp .env.example .env        # Windows: copy .env.example .env
npm run dev

Open the address printed in the terminal (usually http://localhost:5173). The app opens in demo mode, so it works without a backend.


Environment variables (.env)


Variable
	Meaning
	VITE_API_BASE_URL
	Address of the backend, for example http://localhost:8000
	VITE_USE_MOCK
	true = labelled demo data, false = real backend
	

Connect the real backend: set VITE_API_BASE_URL to the backend address and VITE_USE_MOCK=false, make sure the backend allows requests from the frontend's address (CORS), then restart npm run dev.


Production build: npm run build (output in dist/), preview with npm run preview.

08 Disclosures
Libraries (runtime): React and React DOM 18 (MIT), Axios (MIT). Build tooling: Vite and @vitejs/plugin-react (MIT). Font: Jost via Google Fonts (SIL Open Font License). Loaded from Google's servers at runtime, with a system-font fallback if offline.


Templates and UI kits: none. No starter template, component library, CSS framework or icon pack was used. The layout, styles, the animated "W" logo and the demo content were written for this project.


AI tools: the code in this repository was written with Claude (AI assistant by Anthropic) from the team's written screen specifications. Claude generated the React components, CSS, demo data, data adapters, build configuration and this README, and was used to review and fix its own output. Screen requirements, product decisions, risk-level definitions and review were provided by the Weblyze team. Automated checks (Vitest, jsdom, Testing Library) were run locally during development and are not part of this repository.


Data: all sample reports, threats and certificates are fictional and marked DEMO DATA. Sample domains use the reserved .example ending, so they never point at real websites. No real scan results, user data or credentials are included.

09 Track
main
