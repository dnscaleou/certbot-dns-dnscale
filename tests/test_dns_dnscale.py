"""Tests for the DNScale certbot DNS plugin."""

import unittest
from unittest.mock import MagicMock, patch, PropertyMock

import requests

from certbot_dns_dnscale.dns_dnscale import _DNScaleClient


class TestDNScaleClient(unittest.TestCase):
    """Tests for _DNScaleClient."""

    def setUp(self):
        self.client = _DNScaleClient(
            api_token="test-token",
            api_url="https://api.test.dnscale.eu",
        )

    def test_init_sets_auth_header(self):
        self.assertEqual(
            self.client.session.headers["Authorization"],
            "Bearer test-token",
        )

    def test_init_sets_content_type(self):
        self.assertEqual(
            self.client.session.headers["Content-Type"],
            "application/json",
        )

    def test_init_strips_trailing_slash(self):
        client = _DNScaleClient(api_token="t", api_url="https://api.example.com/")
        self.assertEqual(client.api_url, "https://api.example.com")

    # --- add_txt_record ---

    @patch.object(requests.Session, "get")
    @patch.object(requests.Session, "post")
    def test_add_txt_record_success(self, mock_post, mock_get):
        # Mock zone listing
        mock_get_resp = MagicMock()
        mock_get_resp.status_code = 200
        mock_get_resp.json.return_value = {
            "zones": [{"id": "z1", "name": "example.com"}]
        }
        mock_get.return_value = mock_get_resp

        # Mock record creation
        mock_post_resp = MagicMock()
        mock_post_resp.status_code = 201
        mock_post.return_value = mock_post_resp

        self.client.add_txt_record(
            "_acme-challenge.example.com", "challenge-token"
        )

        mock_post.assert_called_once()
        call_args = mock_post.call_args
        self.assertIn("/v1/zones/z1/records", call_args[0][0])
        self.assertEqual(call_args[1]["json"]["type"], "TXT")
        self.assertEqual(call_args[1]["json"]["name"], "_acme-challenge.example.com")
        self.assertEqual(call_args[1]["json"]["content"], "challenge-token")
        self.assertEqual(call_args[1]["json"]["ttl"], 120)

    @patch.object(requests.Session, "get")
    @patch.object(requests.Session, "post")
    def test_add_txt_record_subdomain(self, mock_post, mock_get):
        mock_get_resp = MagicMock()
        mock_get_resp.status_code = 200
        mock_get_resp.json.return_value = {
            "zones": [{"id": "z1", "name": "example.com"}]
        }
        mock_get.return_value = mock_get_resp

        mock_post_resp = MagicMock()
        mock_post_resp.status_code = 201
        mock_post.return_value = mock_post_resp

        self.client.add_txt_record(
            "_acme-challenge.sub.example.com", "token"
        )

        mock_post.assert_called_once()
        call_args = mock_post.call_args
        self.assertIn("/v1/zones/z1/records", call_args[0][0])

    @patch.object(requests.Session, "get")
    @patch.object(requests.Session, "post")
    def test_add_txt_record_api_error(self, mock_post, mock_get):
        mock_get_resp = MagicMock()
        mock_get_resp.status_code = 200
        mock_get_resp.json.return_value = {
            "zones": [{"id": "z1", "name": "example.com"}]
        }
        mock_get.return_value = mock_get_resp

        mock_post_resp = MagicMock()
        mock_post_resp.status_code = 403
        mock_post_resp.text = "forbidden"
        mock_post.return_value = mock_post_resp

        from certbot.errors import PluginError

        with self.assertRaises(PluginError):
            self.client.add_txt_record(
                "_acme-challenge.example.com", "token"
            )

    @patch.object(requests.Session, "get")
    def test_add_txt_record_zone_not_found(self, mock_get):
        mock_get_resp = MagicMock()
        mock_get_resp.status_code = 200
        mock_get_resp.json.return_value = {
            "zones": [{"id": "z1", "name": "other.com"}]
        }
        mock_get.return_value = mock_get_resp

        from certbot.errors import PluginError

        with self.assertRaises(PluginError):
            self.client.add_txt_record(
                "_acme-challenge.example.com", "token"
            )

    # --- del_txt_record ---

    @patch.object(requests.Session, "get")
    @patch.object(requests.Session, "delete")
    def test_del_txt_record_success(self, mock_delete, mock_get):
        mock_get_resp = MagicMock()
        mock_get_resp.status_code = 200
        mock_get_resp.json.return_value = {
            "zones": [{"id": "z1", "name": "example.com"}]
        }
        mock_get.return_value = mock_get_resp

        mock_del_resp = MagicMock()
        mock_del_resp.status_code = 204
        mock_delete.return_value = mock_del_resp

        self.client.del_txt_record(
            "_acme-challenge.example.com", "challenge-token"
        )

        mock_delete.assert_called_once()
        call_args = mock_delete.call_args
        self.assertIn("/v1/zones/z1/records/by-name/_acme-challenge.example.com/TXT", call_args[0][0])
        self.assertEqual(call_args[1]["params"]["content"], "challenge-token")

    @patch.object(requests.Session, "get")
    @patch.object(requests.Session, "delete")
    def test_del_txt_record_zone_not_found_skips(self, mock_delete, mock_get):
        """Cleanup should gracefully skip if zone is not found."""
        mock_get_resp = MagicMock()
        mock_get_resp.status_code = 200
        mock_get_resp.json.return_value = {"zones": []}
        mock_get.return_value = mock_get_resp

        # Should NOT raise — cleanup is best-effort
        self.client.del_txt_record(
            "_acme-challenge.example.com", "token"
        )
        mock_delete.assert_not_called()

    @patch.object(requests.Session, "get")
    @patch.object(requests.Session, "delete")
    def test_del_txt_record_api_error_warns(self, mock_delete, mock_get):
        """Delete failure should warn, not raise."""
        mock_get_resp = MagicMock()
        mock_get_resp.status_code = 200
        mock_get_resp.json.return_value = {
            "zones": [{"id": "z1", "name": "example.com"}]
        }
        mock_get.return_value = mock_get_resp

        mock_del_resp = MagicMock()
        mock_del_resp.status_code = 500
        mock_del_resp.text = "internal error"
        mock_delete.return_value = mock_del_resp

        # Should NOT raise — cleanup logs a warning
        self.client.del_txt_record(
            "_acme-challenge.example.com", "token"
        )

    # --- _find_zone ---

    @patch.object(requests.Session, "get")
    def test_find_zone_exact_match(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "zones": [{"id": "z1", "name": "example.com"}]
        }
        mock_get.return_value = mock_resp

        zone_id, zone_name = self.client._find_zone("example.com")
        self.assertEqual(zone_id, "z1")
        self.assertEqual(zone_name, "example.com")

    @patch.object(requests.Session, "get")
    def test_find_zone_subdomain_walks_up(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "zones": [{"id": "z1", "name": "example.com"}]
        }
        mock_get.return_value = mock_resp

        zone_id, _ = self.client._find_zone("_acme-challenge.deep.sub.example.com")
        self.assertEqual(zone_id, "z1")

    @patch.object(requests.Session, "get")
    def test_find_zone_case_insensitive(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "zones": [{"id": "z1", "name": "Example.COM"}]
        }
        mock_get.return_value = mock_resp

        zone_id, _ = self.client._find_zone("example.com")
        self.assertEqual(zone_id, "z1")

    @patch.object(requests.Session, "get")
    def test_find_zone_trailing_dot(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "zones": [{"id": "z1", "name": "example.com."}]
        }
        mock_get.return_value = mock_resp

        zone_id, _ = self.client._find_zone("example.com.")
        self.assertEqual(zone_id, "z1")

    @patch.object(requests.Session, "get")
    def test_find_zone_prefers_more_specific(self, mock_get):
        """When both parent and child zones exist, find the most specific match."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "zones": [
                {"id": "z-parent", "name": "example.com"},
                {"id": "z-child", "name": "sub.example.com"},
            ]
        }
        mock_get.return_value = mock_resp

        zone_id, _ = self.client._find_zone("_acme-challenge.sub.example.com")
        self.assertEqual(zone_id, "z-child")

    # --- _list_zones ---

    @patch.object(requests.Session, "get")
    def test_list_zones_pagination(self, mock_get):
        """Pagination should fetch all pages."""
        page1 = MagicMock()
        page1.status_code = 200
        page1.json.return_value = {
            "zones": [{"id": f"z{i}", "name": f"domain{i}.com"} for i in range(100)]
        }

        page2 = MagicMock()
        page2.status_code = 200
        page2.json.return_value = {
            "zones": [{"id": "z-last", "name": "last.com"}]
        }

        mock_get.side_effect = [page1, page2]

        zones = self.client._list_zones()
        self.assertEqual(len(zones), 101)
        self.assertEqual(mock_get.call_count, 2)

    @patch.object(requests.Session, "get")
    def test_list_zones_api_error(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 500
        mock_resp.text = "server error"
        mock_get.return_value = mock_resp

        from certbot.errors import PluginError

        with self.assertRaises(PluginError):
            self.client._list_zones()

    @patch.object(requests.Session, "get")
    def test_list_zones_empty(self, mock_get):
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"zones": []}
        mock_get.return_value = mock_resp

        zones = self.client._list_zones()
        self.assertEqual(zones, [])


if __name__ == "__main__":
    unittest.main()
