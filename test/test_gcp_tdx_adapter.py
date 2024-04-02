"""
Copyright (c) 2024 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""

import unittest
from unittest.mock import patch, MagicMock
from inteltrustauthorityclient.src.tdx.gcp.gcp_tdx_adapter import *


def adapter_object():
    """This method initializes GCP TDX Adapter object"""
    return GCPTDXAdapter("user_data")


class GCPAdapterTestCase(unittest.TestCase):
    """class GCPAdapterTestCase that inherits from unittest.TestCase"""

    def test_collect_evidence_with_nonce_and_user_data(self):
        """Test method to test GCP TDX Adapter with Nonce and Userdata"""
        gcp_adapter = adapter_object()
        with patch("hashlib.sha512") as mock_sha_hash:
            mock_sha_hash.return_value.digest.return_value = b"digest"
            with patch("os.open") as mock_open:
                with patch("fcntl.ioctl") as mock_ioctl:
                    with patch("ctypes.CDLL") as mock_libc:
                        with patch("base64.b64encode") as mock_b64encode:
                            mock_b64encode.return_value.decode.return_value = "quote"
                            with patch("os.close") as mock_close:
                                mock_close.return_value = None
                                evidence = gcp_adapter.collect_evidence(nonce=b"nonce")
                                self.assertIsNotNone(evidence)
                                self.assertEqual(evidence.quote, "quote")

    def test_collect_evidence_without_nonce(self):
        """Test method to test GCP TDX Adapter without Nonce"""
        gcp_adapter = adapter_object()
        with patch("hashlib.sha512") as mock_sha_hash:
            mock_sha_hash.return_value.digest.return_value = b"digestq"
            with patch("os.open") as mock_open:
                with patch("fcntl.ioctl") as mock_ioctl:
                    with patch("ctypes.CDLL") as mock_libc:
                        with patch("base64.b64encode") as mock_b64encode:
                            mock_b64encode.return_value.decode.return_value = "quote"
                            with patch("os.close") as mock_close:
                                mock_close.return_value = None
                                evidence = gcp_adapter.collect_evidence()
                                self.assertIsNotNone(evidence)
                                self.assertEqual(evidence.quote, "quote")

    def test_collect_evidence_with_exception(self):
        """Test method to test GCP TDX Adapter with Raising Exception"""
        gcp_adapter = adapter_object()
        with patch("hashlib.sha512") as mock_sha_hash:
            mock_sha_hash.return_value.digest.return_value = b"digest"
            with patch("os.open") as mock_open:
                with patch("fcntl.ioctl") as mock_ioctl:
                    with patch("ctypes.CDLL") as mock_libc:
                        mock_libc.return_value.memcpy.side_effect = Exception(
                            "Mock Exception"
                        )
                        with patch("os.close") as mock_close:
                            mock_close.return_value = None
                            evidence = gcp_adapter.collect_evidence(nonce=b"nonce")
                            self.assertIsNone(evidence)

    def test_collect_evidence_with_OSError(self):
        """Test method to test GCP TDX Adapter with Raising OS Error"""
        gcp_adapter = adapter_object()
        with patch("hashlib.sha512") as mock_sha_hash:
            mock_sha_hash.return_value.digest.return_value = b"digest"
            with patch("os.open") as mock_open:
                with patch("fcntl.ioctl") as mock_ioctl:
                    with patch("ctypes.CDLL") as mock_libc:
                        mock_libc.return_value.memcpy.side_effect = OSError(
                            "Mock OS Error"
                        )
                        with patch("os.close") as mock_close:
                            mock_close.return_value = None
                            evidence = gcp_adapter.collect_evidence(nonce=b"nonce")
                            self.assertIsNone(evidence)


if __name__ == "__main__":
    unittest.main()
