// DEMO DATA: sample threat reports so the feed isn't empty. ".example" domains never resolve to real sites.
// risk_score uses the shared bands: Low 0-29, Medium 30-59, High Risk 60-79, Critical 80-100.
export const DEMO_THREATS = [
  { _demo: true, id: 'demo-1', url: 'https://secure-login.examplebank-verify.example/account', category: 'brand_impersonation', risk_score: 72, verified: true, reported_at: '2026-11-05T09:12:00Z',
    description: 'Copies a bank’s sign-in page and asks for a one-time code right after the password.' },
  { _demo: true, id: 'demo-2', url: 'https://free-video-player-download.example/get', category: 'malware', risk_score: 91, verified: true, reported_at: '2026-11-04T16:40:00Z',
    description: 'The download button delivers an installer that bundles unwanted software.' },
  { _demo: true, id: 'demo-3', url: 'https://helpdesk-account-recovery.example/reset', category: 'brand_impersonation', risk_score: 81, verified: false, reported_at: '2026-11-03T11:05:00Z',
    description: 'Pretends to be an email provider’s recovery page and collects the account password.' },
  { _demo: true, id: 'demo-4', url: 'https://account-unlock-notice.example/verify', category: 'phishing', risk_score: 68, verified: false, reported_at: '2026-11-02T08:30:00Z',
    description: 'A message claims an account is locked and links to a page that collects login details.' },
  { _demo: true, id: 'demo-5', url: 'https://prize-claim-center.example/winner', category: 'malicious_website', risk_score: 63, verified: false, reported_at: '2026-11-01T19:15:00Z',
    description: 'Traps visitors in endless pop-ups and fake “you’ve won” prompts that ask for personal details.' },
  { _demo: true, id: 'demo-6', url: 'https://parcel-redelivery-fee.example/pay', category: 'phishing', risk_score: 47, verified: true, reported_at: '2026-10-30T13:20:00Z',
    description: 'A fake delivery notice asks for a small “redelivery fee” and card details.' },
  { _demo: true, id: 'demo-7', url: 'https://pdf-converter-online.example/tool', category: 'malware', risk_score: 38, verified: false, reported_at: '2026-10-28T18:45:00Z',
    description: 'A document converter prompts visitors to install a browser extension they didn’t ask for.' },
  { _demo: true, id: 'demo-8', url: 'https://coupon-deals-hub.example/offers', category: 'malicious_website', risk_score: 24, verified: true, reported_at: '2026-10-26T10:00:00Z',
    description: 'Shows aggressive pop-up ads and sends some visitors to unrelated pages.' },
];
