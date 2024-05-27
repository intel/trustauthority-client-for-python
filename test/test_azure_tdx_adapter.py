import unittest
import subprocess
import requests
from unittest.mock import patch, MagicMock
from inteltrustauthorityclient.tdx.azure.azure_tdx_adapter import AzureTDXAdapter


class AzureTDXAdapterTestCase(unittest.TestCase):
    """Class AzureTDXAdapterTestCase that inherits from unittest.TestCase"""

    def test_collect_evidence_without_nonce_and_user_data(self):
        """Test method to test collect_evidence without nonce and user_data"""
        tdx_adapter = AzureTDXAdapter(None)
        with patch("subprocess.run") as mock_run, patch(
            "requests.post"
        ) as mock_post, patch("json.loads") as mock_json_loads, patch(
            "binascii.hexlify"
        ) as mock_hexlify:
            mock_run.return_value = MagicMock(stdout=b"tpm_report")
            
            mock_post.return_value = MagicMock(json=lambda: {"quote": "quote"})
            mock_json_loads.return_value = {
                "user-data": "user_data"
            }  # replace with the value you want json.loads() to return
            mock_hexlify.return_value = b"user_data"  # replace with the value you want binascii.hexlify() to return
            with patch("struct.unpack") as mock_unpack:
                mock_unpack.return_value = [1]
                evidence = tdx_adapter.collect_evidence(nonce=b"nonce")
        self.assertIsNotNone(evidence)

    def test_collect_evidence_with_exception_in_tpm2_nvreadpublic(self):
        """Test method to test collect_evidence with exception in tpm2_nvreadpublic"""
        tdx_adapter = AzureTDXAdapter(user_data="user_data")
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = Exception("Error in tpm2_nvreadpublic")
            evidence = tdx_adapter.collect_evidence(nonce=b"nonce")
        self.assertIsNone(evidence)

    def test_collect_evidence_with_exception_in_tpm2_nvdefine(self):
        """Test method to test collect_evidence with exception in tpm2_nvdefine"""
        tdx_adapter = AzureTDXAdapter(user_data="user_data")
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                subprocess.CalledProcessError(1, "tpm2_nvdefine"),
                None,
            ]
            evidence = tdx_adapter.collect_evidence(nonce=b"nonce")
        self.assertIsNone(evidence)

    def test_collect_evidence_with_exception_in_tpm2_nvwrite(self):
        """Test method to test collect_evidence with exception in tpm2_nvwrite"""
        tdx_adapter = AzureTDXAdapter(user_data="user_data")
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                None,
                subprocess.CalledProcessError(1, "tpm2_nvwrite"),
                None,
            ]
            evidence = tdx_adapter.collect_evidence(nonce=b"nonce")
        self.assertIsNone(evidence)

    def test_collect_evidence_with_exception_in_tpm2_nvread(self):
        """Test method to test collect_evidence with exception in tpm2_nvread"""
        tdx_adapter = AzureTDXAdapter(user_data="user_data")
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = [
                None,
                None,
                subprocess.CalledProcessError(1, "tpm2_nvread"),
                None,
            ]
            evidence = tdx_adapter.collect_evidence(nonce=b"nonce")
        self.assertIsNone(evidence)

    def test_collect_evidence_with_exception_in_requests_post(self):
        """Test method to test collect_evidence with exception in requests.post"""
        tdx_adapter = AzureTDXAdapter(user_data="user_data")
        with patch("requests.post") as mock_post:
            mock_post.side_effect = requests.HTTPError()
            evidence = tdx_adapter.collect_evidence(nonce=b"nonce")
        self.assertIsNone(evidence)

    def test_collect_evidence_with_successful_execution(self):
        """Test method to test collect_evidence with successful execution"""
        tdx_adapter = AzureTDXAdapter(user_data="user_data")
        with patch("subprocess.run") as mock_run, patch(
            "requests.post"
        ) as mock_post, patch("json.loads") as mock_json_loads, patch(
            "binascii.hexlify"
        ) as mock_hexlify:
            mock_run.return_value = MagicMock(stdout=b"tpm_report")
            mock_post.return_value = MagicMock(json=lambda: {"quote": "quote"})
            mock_json_loads.return_value = {
                "user-data": "user_data"
            }  # replace with the value you want json.loads() to return
            mock_hexlify.return_value = b"user_data"  # replace with the value you want binascii.hexlify() to return
            # nonce = b'test_nonce'  # replace with your actual nonce
            # user_data = 'test_data'  # replace with your actual user data
            # evidence = tdx_adapter.collect_evidence(nonce=b"nonce")
            with patch("struct.unpack") as mock_unpack:
                mock_unpack.return_value = [1]
                evidence = tdx_adapter.collect_evidence(nonce=b"nonce")
                # assert evidence != None
        self.assertIsNotNone(evidence)


if __name__ == "__main__":
    unittest.main()
