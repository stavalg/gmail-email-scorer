"""Checks that a request comes from our add-on, used by an allowed Google account.

The add-on sends a Google-signed identity token. We verify Google's signature, the issuer,
the expiry and the audience (our add-on's OAuth client ID), then check the email allowlist.
No shared password exists, so there is nothing to leak.
"""
from fastapi import Header, HTTPException, status
from google.auth import exceptions as google_exceptions
from google.auth.transport import requests as google_requests
from google.oauth2 import id_token

from app.config import get_settings

_google_request = google_requests.Request()


def verify_google_token(token: str, audience: str) -> dict:
    """Returns the token's claims. Raises ValueError if the token is invalid."""
    # 10 s tolerance: a token Google just minted can look "issued in the future" to our clock.
    return id_token.verify_oauth2_token(token, _google_request, audience=audience,
                                        clock_skew_in_seconds=10)


def require_user(authorization: str = Header(default="")) -> str:
    settings = get_settings()
    if settings.dev_skip_auth:
        return "dev@localhost"
    if not settings.oauth_client_id:
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Authentication is not configured")

    scheme, _, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not token:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Missing token")
    try:
        claims = verify_google_token(token, settings.oauth_client_id)
    except ValueError:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "Invalid token") from None
    except google_exceptions.GoogleAuthError:
        # e.g. Google's public keys could not be downloaded
        raise HTTPException(status.HTTP_503_SERVICE_UNAVAILABLE, "Cannot verify token") from None

    email = str(claims.get("email", "")).lower()
    if not claims.get("email_verified") or email not in settings.allowed_emails:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Not allowed")
    return email
