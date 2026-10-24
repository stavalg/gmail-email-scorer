/** Talks to the backend. The Google identity token proves who is calling. */

class AddonError extends Error {
  constructor(kind) {
    super(kind);
    this.name = 'AddonError';
    this.kind = kind;
  }
}

function callBackend(payload) {
  const token = ScriptApp.getIdentityToken();
  if (!token) throw new AddonError('unauthorized');

  const response = UrlFetchApp.fetch(BACKEND_URL + '/v1/analyze', {
    method: 'post',
    contentType: 'application/json',
    payload: JSON.stringify(payload),
    headers: { Authorization: 'Bearer ' + token },
    muteHttpExceptions: true,
  });

  const code = response.getResponseCode();
  if (code === 401 || code === 403) throw new AddonError('unauthorized');
  if (code !== 200) throw new AddonError('backend');
  let data;
  try {
    data = JSON.parse(response.getContentText());
  } catch (err) {
    throw new AddonError('invalid_response');
  }
  return validateResult(data);
}

const VERDICTS = ['safe', 'suspicious', 'malicious'];

/** The backend's answer is checked too: we only display what has the expected shape. */
function validateResult(data) {
  const ok = data !== null && typeof data === 'object'
    && VERDICTS.includes(data.verdict)
    && Number.isInteger(data.score) && data.score >= 0 && data.score <= 100
    && ['findings', 'advice', 'facts', 'notices'].every((key) => Array.isArray(data[key]))
    && data.coverage !== null && typeof data.coverage === 'object';
  if (!ok) throw new AddonError('invalid_response');
  return data;
}
