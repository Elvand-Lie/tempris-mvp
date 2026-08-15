import pytest

from services.microsoft_graph import MicrosoftGraphClient, MicrosoftGraphError
from services.scout_connectors import entra_authentication_method_findings


class Response:
    def __init__(self, status_code=200, payload=None, headers=None):
        self.status_code = status_code
        self._payload = payload or {}
        self.headers = headers or {}

    def json(self):
        return self._payload


class Session:
    def __init__(self, get_responses, post_response=None):
        self.get_responses = list(get_responses)
        self.post_response = post_response or Response(payload={"access_token": "test-token"})
        self.posts = []
        self.gets = []

    def post(self, url, **kwargs):
        self.posts.append((url, kwargs))
        return self.post_response

    def get(self, url, **kwargs):
        self.gets.append((url, kwargs))
        return self.get_responses.pop(0)


def client(session, sleep=lambda _: None):
    return MicrosoftGraphClient("entra-tenant", "client", "secret", session=session, sleep=sleep)


def test_graph_authentication_pagination_and_method_normalization():
    session = Session([
        Response(payload={
            "value": [{"id": "phone", "userPrincipalName": "phone@example.test"}],
            "@odata.nextLink": "https://graph.microsoft.com/v1.0/users?$skiptoken=next",
        }),
        Response(payload={"value": [
            {"id": "passkey", "userPrincipalName": "passkey@example.test"},
            {"id": "empty", "userPrincipalName": "empty@example.test"},
        ]}),
        Response(payload={"value": [{
            "@odata.type": "#microsoft.graph.phoneAuthenticationMethod", "phoneType": "mobile",
        }]}),
        Response(payload={"value": [{"@odata.type": "#microsoft.graph.fido2AuthenticationMethod"}]}),
        Response(payload={"value": []}),
    ])

    snapshot = client(session).authentication_snapshot()

    assert snapshot["users_discovered"] == 3
    assert snapshot["errors"] == []
    assert session.posts[0][1]["data"]["grant_type"] == "client_credentials"
    assert session.gets[0][1]["headers"]["Authorization"] == "Bearer test-token"
    findings = entra_authentication_method_findings(snapshot["users"])
    assert [item["finding_id"] for item in findings] == ["SSS-ENTRA-phone"]


def test_graph_throttling_retries_and_partial_user_failure():
    sleeps = []
    session = Session([
        Response(429, headers={"Retry-After": "1"}),
        Response(payload={"value": [
            {"id": "failed", "userPrincipalName": "failed@example.test"},
            {"id": "ok", "userPrincipalName": "ok@example.test"},
        ]}),
        Response(403),
        Response(payload={"value": []}),
    ])

    snapshot = client(session, sleeps.append).authentication_snapshot()

    assert sleeps == [1.0]
    assert snapshot["users_discovered"] == 2
    assert [user["id"] for user in snapshot["users"]] == ["ok"]
    assert snapshot["errors"] == [{"user": "failed", "error": "Microsoft Graph permissions are insufficient"}]


def test_graph_permission_and_authentication_failures_are_sanitized():
    with pytest.raises(MicrosoftGraphError, match="authentication failed"):
        client(Session([], post_response=Response(401))).authentication_snapshot()

    session = Session([Response(403)])
    with pytest.raises(MicrosoftGraphError, match="permissions are insufficient"):
        client(session).authentication_snapshot()
