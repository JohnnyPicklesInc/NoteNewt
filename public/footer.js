/** Shared site footer with internal links + cross-promo to sibling utilities.
 *  Injected as a module (CSP-safe). Primary content/internal links also live
 *  statically in each page's <main> for SEO; this is supplementary. */
import { renderAd } from './ad.js';
const links = [
  { href: '/', text: 'Home' },
  { href: '/app', text: 'Your notes' },
  { href: '/no-signup-notes', text: 'No-signup notes' },
  { href: '/private-notes-online', text: 'Private notes' },
  { href: '/encrypted-notepad', text: 'Encrypted notepad' },
  { href: '/privacy', text: 'Privacy' },
];
// Sibling first-party utilities (cross-promo network).
const siblings = [
  { href: 'https://whisper-fox.com', text: 'WhisperFox — send a secret' },
  { href: 'https://invoiceiguana.com', text: 'InvoiceIguana — invoice by link' },
];

const el = document.getElementById('siteFooter');
if (el) {
  const nav = links.map((l) => `<a href="${l.href}">${l.text}</a>`).join('');
  const sib = siblings.map((s) => `<a href="${s.href}" rel="noopener">${s.text}</a>`).join('');
  el.innerHTML =
    `<div id="footerAd" class="ad-slot" style="max-width:520px;margin:0 auto 1rem"></div>` +
    `<nav>${nav}</nav>` +
    `<p style="margin-top:0.75rem">More private tools: ${sib}</p>` +
    `<p style="margin-top:0.75rem">🦎 Note Newt · Free &amp; encrypted · <span>No trackers</span></p>`;
  renderAd(document.getElementById('footerAd'));
}
