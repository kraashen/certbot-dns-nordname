"""Unit tests for Nordname DNS Authenticator plugin."""
import pytest
import requests_mock

from certbot import errors

from certbot_dns_nordname.dns_nordname import _NordnameClient


def test_add_txt_record_posts_expected_payload() -> None:
    """
    Test that add_txt_record sends the expected payload to the Nordname API.
    """
    with requests_mock.Mocker() as m:
        m.get(
            "https://api.example.test/domain/example.com/get_dns_zone",
            json=[],
            status_code=200,
        )
        m.post(
            "https://api.example.test/domain/example.com/add_dns_record",
            json={"id": 1},
            status_code=200,
        )

        client = _NordnameClient(token="abc123", endpoint="https://api.example.test")
        client.add_txt_record(
            domain="example.com",
            record_name="_acme-challenge.example.com",
            record_content="token-value",
            ttl=60,
        )

        add_request = m.request_history[-1]
        assert add_request.headers["Authorization"] == "token abc123"
        assert add_request.qs["type"] == ["txt"]
        assert add_request.qs["name"] == ["_acme-challenge"]
        assert add_request.qs["content"] == ["token-value"]
        assert add_request.qs["ttl"] == ["60"]


def test_del_txt_record_deletes_matching_record() -> None:
    """
    Test that del_txt_record finds the correct record ID and sends a delete request.
    """
    with requests_mock.Mocker() as m:
        m.get(
            "https://api.example.test/domain/example.com/get_dns_zone",
            # Nordname stores TXT content with surrounding double-quotes
            json=[
                {
                    "id": 42,
                    "type": "TXT",
                    "name": "_acme-challenge",
                    "content": '"token-value"',
                }
            ],
            status_code=200,
        )
        m.delete(
            "https://api.example.test/domain/example.com/delete_dns_record",
            text="",
            status_code=200,
        )

        client = _NordnameClient(token="abc123", endpoint="https://api.example.test")
        client.del_txt_record(
            domain="example.com",
            record_name="_acme-challenge.example.com",
            record_content="token-value",
        )

        assert m.call_count == 3
        delete_request = m.request_history.pop()
        assert delete_request.qs["id"] == ["42"]


def test_del_txt_record_does_nothing_when_record_missing() -> None:
    """
    Test that del_txt_record does not raise an error when the record is not found.
    """
    with requests_mock.Mocker() as m:
        m.get("https://api.example.test/domain/example.com/get_dns_zone", json=[], status_code=200)

        client = _NordnameClient(token="abc123", endpoint="https://api.example.test")
        client.del_txt_record(
            domain="example.com",
            record_name="_acme-challenge.example.com",
            record_content="token-value",
        )

        assert m.call_count == 2


def test_add_txt_record_discovers_parent_zone() -> None:
    """
    Test that zone discovery tries parent domains when subdomain zone doesn't exist.
    """
    with requests_mock.Mocker() as m:
        m.get(
            "https://api.example.test/domain/sub.example.com/get_dns_zone",
            json={"status": 404, "detail": "Zone not found"},
            status_code=404,
        )
        m.get(
            "https://api.example.test/domain/example.com/get_dns_zone",
            json=[],
            status_code=200,
        )
        m.post(
            "https://api.example.test/domain/example.com/add_dns_record",
            json={"id": 1},
            status_code=200,
        )

        client = _NordnameClient(token="abc123", endpoint="https://api.example.test")
        client.add_txt_record(
            domain="sub.example.com",
            record_name="_acme-challenge.sub.example.com",
            record_content="token-value",
            ttl=60,
        )

        add_request = m.request_history[-1]
        assert "add_dns_record" in add_request.url
        assert "example.com" in add_request.url

        assert add_request.qs["name"] == ["_acme-challenge.sub"]


def test_add_txt_record_fails_when_no_zone_found() -> None:
    """Test that we raise a helpful error when no zone can be found."""
    with requests_mock.Mocker() as m:

        m.get(
            "https://api.example.test/domain/notfound.example.com/get_dns_zone",
            json={"status": 404, "detail": "Zone not found"},
            status_code=404,
        )
        m.get(
            "https://api.example.test/domain/example.com/get_dns_zone",
            json={"status": 404, "detail": "Zone not found"},
            status_code=404,
        )
        m.get(
            "https://api.example.test/domain/com/get_dns_zone",
            json={"status": 404, "detail": "Zone not found"},
            status_code=404,
        )

        client = _NordnameClient(token="abc123", endpoint="https://api.example.test")

        with pytest.raises(errors.PluginError) as exc_info:
            client.add_txt_record(
                domain="notfound.example.com",
                record_name="_acme-challenge.notfound.example.com",
                record_content="token-value",
                ttl=60,
            )

        assert "Could not find a DNS zone" in str(exc_info.value)
