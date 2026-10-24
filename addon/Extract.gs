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

function extractEmail(message) {
  let truncated = false;
  const cut = (value, max) => {
    const text = value || '';
    if (text.length > max) {
      truncated = true;
      return text.slice(0, max);
    }
    return text;
  };

  const raw = message.getRawContent();
  const headerEnd = raw.search(/\r?\n\r?\n/);
  const headers = headerEnd === -1 ? raw : raw.slice(0, headerEnd);

  const all = message.getAttachments({ includeInlineImages: false, includeAttachments: true });
  if (all.length > LIMITS.ATTACHMENTS) truncated = true;

  const payload = {
    headers_raw: cut(headers, LIMITS.HEADERS_CHARS),
    body_html: cut(message.getBody(), LIMITS.HTML_CHARS),
    body_text: cut(message.getPlainBody(), LIMITS.TEXT_CHARS),
    attachments: all.slice(0, LIMITS.ATTACHMENTS).map(describeAttachment),
  };
  payload.truncated = truncated;
  return payload;
}

function describeAttachment(attachment) {
  const size = attachment.getSize();
  return {
    name: (attachment.getName() || '').slice(0, LIMITS.NAME_CHARS),
    content_type: (attachment.getContentType() || '').slice(0, LIMITS.TYPE_CHARS),
    size: size,
    // Only a fingerprint is sent, so the backend can look it up without seeing the file.
    sha256: size <= LIMITS.HASH_MAX_BYTES ? sha256Hex(attachment.getBytes()) : null,
  };
}

function sha256Hex(bytes) {
  const digest = Utilities.computeDigest(Utilities.DigestAlgorithm.SHA_256, bytes);
  return digest.map((b) => ((b + 256) % 256).toString(16).padStart(2, '0')).join('');
}
