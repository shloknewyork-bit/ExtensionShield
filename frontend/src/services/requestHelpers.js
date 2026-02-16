function extractDetailFromBody(body) {
  if (!body) return null;
  if (typeof body === "string") return body;
  if (typeof body === "object") return body;
  return null;
}

function formatErrorMessage(detail, fallbackMessage) {
  if (!detail) return fallbackMessage;
  if (typeof detail === "string") return detail;

  return (
    detail?.message ||
    detail?.error ||
    detail?.detail ||
    fallbackMessage
  );
}

export async function fetchJson(url, options = {}) {
  const response = await fetch(url, options);
  let body = null;
  try {
    body = await response.json();
  } catch {
    body = null;
  }
  return { response, body };
}

export function buildFetchError(response, body, fallbackMessage = "Request failed") {
  const detail = extractDetailFromBody(body);
  const message = formatErrorMessage(detail, fallbackMessage);
  const err = new Error(message);
  err.status = response?.status;
  err.detail = detail;
  return err;
}
