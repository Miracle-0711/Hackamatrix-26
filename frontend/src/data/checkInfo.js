// Plain-language explanations of well-known checks. General knowledge about what each setting does,
// not scan results. Unknown check names simply show no explanation.
const INFO = {
  'content-security-policy': 'Tells the browser which sources a page may load scripts and content from. It limits the damage if an attacker manages to inject code.',
  'strict-transport-security': 'Tells browsers to always use HTTPS for this site, which stops downgrade and interception attacks.',
  'x-frame-options': 'Stops other sites from showing this page inside a frame, which blocks clickjacking.',
  'x-content-type-options': 'Stops browsers from guessing file types, so uploaded content can’t be mistaken for a script.',
  'referrer-policy': 'Controls how much of the page address is shared with other sites when a visitor clicks a link.',
  secure: 'A cookie marked Secure is only sent over HTTPS, so it can’t be read on an unencrypted connection.',
  httponly: 'A cookie marked HttpOnly can’t be read by page scripts, which protects login sessions if a script is compromised.',
  samesite: 'SameSite limits when a cookie is sent with requests from other sites, which reduces cross-site request attacks.',
};
export const explain = (name = '') => INFO[name.toLowerCase().replace(/[\s_-]+/g, name.includes('-') ? '-' : '')] ?? INFO[name.toLowerCase().replace(/[\s_-]+/g, '')] ?? null;
