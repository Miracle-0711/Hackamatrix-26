// DEMO DATA: a predefined sample investigation for exploring the report without a backend.
// The domain uses the reserved ".example" TLD, so it never points at a real site.
// Same shape as a real result, so it exercises the same code path.
export const DEMO_RAW = {
  _demo: true,
  url: 'https://secure-login.examplebank-verify.example/account',
  risk_score: 72,
  risk_level: 'High Risk',
  completed_at: '2026-11-07T10:30:00Z',
  summary: 'In this sample, the page imitates a bank sign-in form on a very new domain and sends visitors through several redirects before asking for a password. A real site behaving this way should be treated as unsafe.',
  checks: {
    threat_detection: {
      status: 'fail',
      findings: ['The sign-in form sends passwords to a different domain than the one shown', 'The page asks for a one-time code right after the password'],
      explanation: 'These behaviours are typical of pages built to capture credentials rather than serve real customers.',
    },
    domain_intelligence: {
      status: 'warn',
      findings: ['Domain registered 3 days ago (sample)', 'Registrant details hidden'],
      explanation: 'Established organisations rarely run sign-in pages on brand-new domains with hidden ownership.',
    },
    ssl_tls: {
      status: 'pass',
      findings: ['Certificate is valid and not expired', 'Certificate issued to the same domain'],
      explanation: 'A valid certificate only means the connection is encrypted. It does not prove the site is trustworthy.',
    },
    brand_impersonation: {
      status: 'fail',
      findings: ['Page title and logo imitate a fictional brand, ExampleBank', 'Domain name contains the brand name but is not the brand’s own'],
      explanation: 'Attackers often borrow a trusted name in the domain to make a fake page look official.',
    },
    redirect_analysis: {
      status: 'warn',
      findings: ['3 redirects before the final page', 'One redirect passes through a URL shortener'],
      explanation: 'Long redirect chains can hide where a link really leads.',
    },
    security_assessment: {
      status: 'warn',
      findings: ['No content security policy', 'No HSTS header'],
      explanation: 'Missing protections make a site easier to tamper with and are common on hastily built pages.',
    },
  },
  recommendations: [
    { risk: 'Credentials may be captured by the sign-in form', action: 'Do not enter your password or one-time codes on this page.' },
    { risk: 'The site imitates a trusted brand', action: 'Open the organisation’s own website by typing its address yourself, instead of using this link.' },
    { risk: 'The link was reached through hidden redirects', action: 'Do not forward or share this link. Report it to whoever sent it to you.' },
    { risk: 'You may already have visited it', action: 'If you entered details here, change that password straight away and watch for unusual account activity.' },
  ],
};
