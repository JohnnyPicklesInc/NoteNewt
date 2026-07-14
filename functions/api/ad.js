/**
 * GET /api/ad  ->  { text, link, image?, view_url? }
 *
 * Fetches the ad decision server-side and returns plain data; the client renders
 * it as first-party HTML, so no third-party script ever runs next to a note.
 * With no publisher configured it returns a first-party "house" ad that
 * cross-promotes a sibling utility.
 */
import { json } from '../_http.js';

// First-party house ads cross-promoting sibling utilities. One is chosen at
// random per request when no paid publisher is configured.
const HOUSE_ADS = [
  {
    type: 'house',
    text: '🦊 WhisperFox — share passwords & secrets by self-destructing link.',
    link: 'https://whisper-fox.com',
    image: null,
    view_url: null,
  },
  {
    type: 'house',
    text: '🧾 InvoiceIguana — turn an invoice or receipt into a shareable link. No signup.',
    link: 'https://invoiceiguana.com',
    image: null,
    view_url: null,
  },
];

function houseAd() {
  return HOUSE_ADS[Math.floor(Math.random() * HOUSE_ADS.length)];
}

export async function onRequestGet({ env }) {
  const publisher = env.ETHICALADS_PUBLISHER;
  if (!publisher) return json(houseAd());

  try {
    const url =
      'https://server.ethicalads.io/api/v1/decision/' +
      `?publisher=${encodeURIComponent(publisher)}` +
      '&ad_types=image.v1&keywords=privacy,productivity,writing';
    const r = await fetch(url, { headers: { accept: 'application/json' } });
    if (!r.ok) return json(houseAd());
    const d = await r.json();
    if (!d || (!d.body && !d.image)) return json(houseAd());
    return json({
      type: 'ethicalads',
      text: stripTags(d.body || ''),
      link: httpUrl(d.link) || '/',
      image: httpUrl(d.image),
      view_url: httpUrl(d.view_url), // first-party <img> impression pixel
    });
  } catch {
    return json(houseAd());
  }
}

/** Remove HTML tags from an ad body, leaving plain text. */
function stripTags(s) {
  return String(s || '').replace(/<[^>]*>/g, '').trim();
}

/**
 * Pass a URL through only if it parses as http(s); anything else (javascript:,
 * data:, relative junk) becomes null. The ad server is semi-trusted.
 * @param {unknown} u
 * @returns {string | null}
 */
function httpUrl(u) {
  if (typeof u !== 'string' || !u) return null;
  try {
    const parsed = new URL(u);
    return parsed.protocol === 'http:' || parsed.protocol === 'https:' ? u : null;
  } catch {
    return null;
  }
}
