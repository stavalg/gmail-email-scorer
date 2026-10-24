/** Collects the minimum data the backend needs. Attachment contents never leave Gmail. */

const LIMITS = {
  HEADERS_CHARS: 65536,
  HTML_CHARS: 500000,
  TEXT_CHARS: 100000,
  ATTACHMENTS: 50,
  NAME_CHARS: 1024,
  TYPE_CHARS: 255,
  HASH_MAX_BYTES: 10 * 1024 * 1024,
};

/**
 * Cuts text to at most `max` UTF-16 units without splitting an emoji (a surrogate pair):
 * half a character is invalid text and the backend would reject the whole email.
 */
function truncate(value, max) {
  const text = value || '';
  if (text.length <= max) return { text: text, cut: false };
  let end = max;
  const last = text.charCodeAt(end - 1);
  if (last >= 0xD800 && last <= 0xDBFF) end -= 1;  // high surrogate: its pair was cut off
  return { text: text.slice(0, end), cut: true };
}

/** Builds the request for the backend: headers, body and attachment metadata, cut to safe sizes. */
function extractEmail(message) {
  let truncated = false;
  const cut = (value, max) => {
    const result = truncate(value, max);
    if (result.cut) truncated = true;
    return result.text;
  };

  const raw = message.getRawContent();
  const headerEnd = raw.search(/\r?\n\r?\n/);
  const headers = headerEnd === -1 ? raw : raw.slice(0, headerEnd);

  const all = message.getAttachments({ includeInlineImages: false, includeAttachments: true });
  if (all.length > LIMITS.ATTACHMENTS) truncated = true;

  const payload = {
    headers_raw: cut(headers, LIMITS.HEADERS_CHARS),
    body_html: cut(redactSecrets(message.getBody()), LIMITS.HTML_CHARS),
    body_text: cut(redactSecrets(message.getPlainBody()), LIMITS.TEXT_CHARS),
    attachments: all.slice(0, LIMITS.ATTACHMENTS).map(describeAttachment),
  };
  payload.truncated = truncated;
  return payload;
}

// Redaction: secrets meant for the reader (reset tokens, one-time codes, passwords) are removed
// here, so the backend never sees them. Everything the rules read stays: link schemes and hosts,
// redirect targets, and words like "password".
const URL_IN_TEXT = /https?:\/\/[^\s<>"')\]]+/gi;  // the same pattern the backend uses
const SENSITIVE_PARAM = /token|code|key|pass|pwd|secret|sig|auth|session|sid|otp|ticket|nonce|hash/i;
const LOGIN_TOKEN = /^eyJ[\w-]+\.[\w-]+\.[\w-]*$/;  // the three-part shape of a JWT
const DOMAIN = /^([a-z0-9-]+\.)+[a-z]{2,}$/i;
const PASSWORD_VALUE = /\b(password|passcode|pin|pwd)(\s*:\s*|\s+is:?\s+)((?:<[^>]*>\s*)*)([^\s<]+)/gi;
const ONE_TIME_CODE = /\b(code|otp|passcode|one-time|verification)\b((?:[^\d<]|<[^>]*>){0,30}?)(\d{4,8})\b/gi;

/** Removes secrets from email text or HTML before it leaves Gmail. */
function redactSecrets(text) {
  return (text || '')
    .replace(URL_IN_TEXT, (match) => {
      const trail = match.match(/[.,;:!?]*$/)[0];  // sentence punctuation is not part of the link
      return redactUrl(match.slice(0, match.length - trail.length)) + trail;
    })
    .replace(PASSWORD_VALUE, (match, word, separator, tags, value) => {
      // "password: x" always hides x; "password is x" only when x looks like one, not "is correct".
      const hide = separator.includes(':') || /[^a-z]/i.test(value);
      return hide ? word + separator + tags + '[hidden]' : match;
    })
    .replace(ONE_TIME_CODE, (match, word, gap) => word + gap + '[code]');
}

/** One link with its secrets removed: random path pieces, sensitive parameters, everything after #. */
function redactUrl(url) {
  const noFragment = url.split('#')[0];
  const queryStart = noFragment.indexOf('?');
  const base = queryStart === -1 ? noFragment : noFragment.slice(0, queryStart);
  const pathStart = base.indexOf('/', base.indexOf('//') + 2);
  const host = pathStart === -1 ? base : base.slice(0, pathStart);
  const path = pathStart === -1 ? '' : base.slice(pathStart)
    .split('/').map((piece) => (looksRandom(piece, 20) ? 'REDACTED' : piece)).join('/');
  if (queryStart === -1) return host + path;
  const query = noFragment.slice(queryStart + 1)
    .split(/(&amp;|&)/)  // keeps the separators; HTML writes & as &amp;
    .map((part, i) => (i % 2 ? part : redactParam(part)))
    .join('');
  return host + path + '?' + query;
}

/** One "name=value" parameter, its value hidden when the name or the value looks secret. */
function redactParam(part) {
  const eq = part.indexOf('=');
  const name = eq === -1 ? '' : part.slice(0, eq);
  const value = eq === -1 ? part : part.slice(eq + 1);
  const prefix = eq === -1 ? '' : name + '=';
  if (!value) return part;
  if (SENSITIVE_PARAM.test(name)) return prefix + 'REDACTED';
  let decoded = value;
  try { decoded = decodeURIComponent(value); } catch (e) { /* not encoded: use as is */ }
  if (/^https?:\/\//i.test(decoded)) {
    // A redirect target keeps its domain for future checks, cleaned like any other link.
    const cleaned = redactUrl(decoded);
    return prefix + (decoded === value ? cleaned : encodeURIComponent(cleaned));
  }
  if (LOGIN_TOKEN.test(decoded)) return prefix + 'REDACTED';
  if (DOMAIN.test(decoded)) return part;
  return prefix + (looksRandom(value, 16) ? 'REDACTED' : value);
}

/** True for long letter-and-digit soup, the usual shape of a token. */
function looksRandom(value, minLength) {
  return value.length >= minLength && /^[\w\-.~%+=]+$/.test(value) && /[a-z]/i.test(value) && /\d/.test(value);
}

/** Name, type, size and SHA-256 fingerprint of one attachment (files over 10 MB are not hashed). */
function describeAttachment(attachment) {
  const size = attachment.getSize();
  return {
    name: truncate(attachment.getName(), LIMITS.NAME_CHARS).text,
    content_type: truncate(attachment.getContentType(), LIMITS.TYPE_CHARS).text,
    size: size,
    // Only a fingerprint is sent, so the backend can look it up without seeing the file.
    sha256: size <= LIMITS.HASH_MAX_BYTES ? sha256Hex(attachment.getBytes()) : null,
  };
}

/** The SHA-256 fingerprint of a file, as hex text. */
function sha256Hex(bytes) {
  const digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, bytes);
  return digest.map((b) => ((b + 256) % 256).toString(16).padStart(2, '0')).join('');
}
