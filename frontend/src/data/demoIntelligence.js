// DEMO DATA: sample security intelligence for exploring the screen without a backend.
// Matches the sample investigation in demoReport.js. ".example" domains never resolve to real sites.
export const DEMO_INTEL = {
  _demo: true,
  intelligence: {
    certificate: {
      status: 'valid',
      issuer: 'Example Trust CA R1 (sample)',
      issued_at: '2026-11-04T00:00:00Z',
      expires_at: '2027-02-05T00:00:00Z',
      summary: 'The certificate is valid and matches the domain. That only proves the connection is encrypted, not that the site is trustworthy.',
      issues: [],
      chain: [
        { role: 'root', name: 'Example Root CA', status: 'pass' },
        { role: 'intermediate', name: 'Example Trust CA R1', status: 'pass' },
        { role: 'leaf', name: 'secure-login.examplebank-verify.example', status: 'pass' },
      ],
      details: { subject: 'secure-login.examplebank-verify.example', signature: 'SHA-256 with RSA', key_size: '2048-bit', protocol: 'TLS 1.3' },
    },
    redirects: {
      status: 'warning',
      summary: 'Three redirects before the final page, including a URL shortener and one unencrypted hop.',
      chain: [
        { url: 'https://secure-login.examplebank-verify.example/account', status_code: 302 },
        { url: 'https://short.example/x7Qp2', status_code: 301, suspicious: true, reason: 'A URL shortener hides the real destination.' },
        { url: 'http://track.examplebank-verify.example/go?id=118', status_code: 302, suspicious: true, reason: 'Unencrypted hop: traffic could be read or changed.' },
        { url: 'https://login.examplebank-verify.example/session', status_code: 200 },
      ],
      details: { total_redirects: 3, final_status: '200 OK' },
    },
    security: {
      status: 'warning',
      summary: 'Several protections are missing. This is common on hastily built pages.',
      headers: [
        { name: 'Content-Security-Policy', status: 'fail', note: 'Missing. Pages can load scripts from any source.' },
        { name: 'Strict-Transport-Security', status: 'warning', note: 'Missing. Browsers aren’t told to always use HTTPS.' },
        { name: 'X-Frame-Options', status: 'warning', note: 'Missing. The page could be embedded in another site.' },
        { name: 'X-Content-Type-Options', status: 'pass', note: 'Present.' },
        { name: 'Referrer-Policy', status: 'pass', note: 'Present.' },
      ],
      cookies: [
        { name: 'Secure', status: 'warning', note: '1 of 2 cookies is missing it: “session”.' },
        { name: 'HttpOnly', status: 'warning', note: '1 of 2 cookies is missing it: “session”.' },
        { name: 'SameSite', status: 'pass', note: 'Set on both cookies (Lax).' },
      ],
      details: { server_header: 'Hidden', http_version: 'HTTP/2' },
    },
  },
};
