"""Minimal Microsoft Graph acquisition for the existing Entra posture normalizer."""

from __future__ import annotations

import os
import time
from urllib.parse import quote, urlparse

import requests


class MicrosoftGraphError(RuntimeError):
    def __init__(self, message: str, *, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


class MicrosoftGraphClient:
    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str,
        *,
        graph_base_url: str = "https://graph.microsoft.com/v1.0",
        session=None,
        sleep=time.sleep,
    ):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.graph_base_url = graph_base_url.rstrip("/")
        self.session = session or requests.Session()
        self.sleep = sleep
        self.access_token: str | None = None

    @classmethod
    def from_env(cls, owner_tenant_id: str, **kwargs):
        configured_owner = os.environ.get("ENTRA_GRAPH_OWNER_TENANT_ID", "")
        tenant_id = os.environ.get("ENTRA_GRAPH_TENANT_ID", "")
        client_id = os.environ.get("ENTRA_GRAPH_CLIENT_ID", "")
        client_secret = os.environ.get("ENTRA_GRAPH_CLIENT_SECRET", "")
        if not configured_owner or configured_owner != owner_tenant_id:
            raise MicrosoftGraphError("Microsoft Graph is not configured for this Tempris tenant")
        if not all((tenant_id, client_id, client_secret)):
            raise MicrosoftGraphError("Microsoft Graph credentials are not configured")
        return cls(
            tenant_id,
            client_id,
            client_secret,
            graph_base_url=os.environ.get("ENTRA_GRAPH_BASE_URL", "https://graph.microsoft.com/v1.0"),
            **kwargs,
        )

    def authenticate(self) -> None:
        url = f"https://login.microsoftonline.com/{quote(self.tenant_id, safe='')}/oauth2/v2.0/token"
        try:
            response = self.session.post(url, data={
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "grant_type": "client_credentials",
                "scope": "https://graph.microsoft.com/.default",
            }, timeout=20)
        except requests.RequestException as exc:
            raise MicrosoftGraphError("Microsoft Graph authentication request failed") from exc
        if response.status_code >= 400:
            raise MicrosoftGraphError("Microsoft Graph authentication failed", status_code=response.status_code)
        token = response.json().get("access_token")
        if not token:
            raise MicrosoftGraphError("Microsoft Graph authentication returned no access token")
        self.access_token = token

    def _validate_next_link(self, url: str) -> str:
        expected = urlparse(self.graph_base_url)
        candidate = urlparse(url)
        if candidate.scheme != "https" or candidate.netloc != expected.netloc:
            raise MicrosoftGraphError("Microsoft Graph returned an unsafe pagination link")
        return url

    def _get(self, url: str, *, params=None) -> dict:
        if not self.access_token:
            self.authenticate()
        for attempt in range(3):
            try:
                response = self.session.get(
                    url,
                    params=params,
                    headers={"Authorization": f"Bearer {self.access_token}"},
                    timeout=30,
                )
            except requests.RequestException as exc:
                if attempt == 2:
                    raise MicrosoftGraphError("Microsoft Graph request failed") from exc
                self.sleep(2 ** attempt)
                continue
            if response.status_code == 429 or response.status_code >= 500:
                if attempt == 2:
                    raise MicrosoftGraphError("Microsoft Graph retry limit reached", status_code=response.status_code)
                try:
                    delay = min(float(response.headers.get("Retry-After", 2 ** attempt)), 5)
                except (TypeError, ValueError):
                    delay = 2 ** attempt
                self.sleep(delay)
                continue
            if response.status_code in (401, 403):
                raise MicrosoftGraphError("Microsoft Graph permissions are insufficient", status_code=response.status_code)
            if response.status_code >= 400:
                raise MicrosoftGraphError("Microsoft Graph request failed", status_code=response.status_code)
            return response.json()
        raise MicrosoftGraphError("Microsoft Graph request failed")

    def _paged(self, url: str, *, params=None) -> list[dict]:
        values: list[dict] = []
        next_url: str | None = url
        next_params = params
        while next_url:
            payload = self._get(next_url, params=next_params)
            values.extend(payload.get("value") or [])
            raw_next = payload.get("@odata.nextLink")
            next_url = self._validate_next_link(raw_next) if raw_next else None
            next_params = None
        return values

    def authentication_snapshot(self) -> dict:
        users = self._paged(
            f"{self.graph_base_url}/users",
            params={"$select": "id,userPrincipalName,mail"},
        )
        collected, errors = [], []
        for user in users:
            user_id = user.get("id")
            if not user_id:
                errors.append({"user": "unknown", "error": "missing_user_id"})
                continue
            try:
                methods = self._paged(
                    f"{self.graph_base_url}/users/{quote(str(user_id), safe='')}/authentication/methods"
                )
            except MicrosoftGraphError as exc:
                errors.append({"user": str(user_id), "error": str(exc)})
                continue
            collected.append({**user, "authenticationMethods": methods})
        return {"users": collected, "users_discovered": len(users), "errors": errors}


def acquire_entra_authentication_snapshot(owner_tenant_id: str) -> dict:
    return MicrosoftGraphClient.from_env(owner_tenant_id).authentication_snapshot()
