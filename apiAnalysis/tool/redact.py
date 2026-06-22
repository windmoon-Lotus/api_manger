from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


SENSITIVE_QUERY_KEYS = {
    "_token",
    "access_token",
    "auth",
    "authorization",
    "bearer",
    "code",
    "jwt",
    "refresh_token",
    "session",
    "sid",
    "ticket",
    "token",
    "user_token",
}


def redact_url(url):
    if not url:
        return url
    parts = urlsplit(url)
    if not parts.query:
        return url
    redacted_query = []
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        if key.lower() in SENSITIVE_QUERY_KEYS or "token" in key.lower():
            redacted_query.append((key, "***REDACTED***"))
        else:
            redacted_query.append((key, value))
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(redacted_query), parts.fragment))
