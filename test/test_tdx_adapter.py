"""
Copyright (c) 2024 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""

import unittest
from unittest.mock import patch, MagicMock
from src.tdx.tdx_adapter import *


def adapter_object():
    """This method initializes TDX Adapter object"""
    return TDXAdapter()


class TDXAdapterTestCase(unittest.TestCase):
    """class TDXAdapterTestCase that inherits from unittest.TestCase"""

    def test_adpater(self):
        """Test method to test TDX Adapter"""
        tdx_adapter = adapter_object()

        def mock_cdll(arg1):
            return None

        with patch.object(ctypes, "CDLL", new=mock_cdll):
            with patch("ctypes.CDLL") as mock_cdll:
                mock_cdll.return_value.tdx_att_get_quote.return_value = 0
                with patch("hashlib.sha512") as mock_sha_hash:
                    mock_sha_hash.update = None
                    mock_cdll.return_value.tdx_att_free_quote.return_value = 0
                    evidence = tdx_adapter.collect_evidence("")
                    assert evidence != None

    def test_adpater_file_notfound_error(self):
        """Test method to test TDX Adapter with File Not found Error"""
        tdx_adapter = adapter_object()
        evidence = tdx_adapter.collect_evidence()
        assert evidence == None

    def test_adpater_dcap_load_error(self):
        """Test method to test TDX Adapter with raising Dcap Load Error"""
        tdx_adapter = adapter_object()

        def mock_cdll(arg1):
            raise OSError("Error in loading library")

        with patch.object(ctypes, "CDLL", new=mock_cdll):
            evidence = tdx_adapter.collect_evidence()
            assert evidence == None

    # def test_adapter_dcap_load_error(self):
    #     """Test method to test TDX Adapter with raising Dcap Load Error"""
    #     tdx_adapter = adapter_object()

    #     # Define a mock function for tdx_att_get_quote that returns 0
    #     def mock_tdx_att_get_quote(tdx_report, _, __, tdx_uuid, quote_buffer, quote_size, ___):
    #         return 0

    #     # Patch the CDLL constructor to return None
    #     with patch('ctypes.CDLL', return_value=None):
    #         # Patch the tdx_att_get_quote function to return 0
    #         with patch('ctypes.CDLL.tdx_att_get_quote', new=mock_tdx_att_get_quote):
    #             evidence = tdx_adapter.collect_evidence()

    #     # Assert that the evidence is None
    #     self.assertIsNone(evidence)

    def test_adpater_memory_error(self):
        """Test method to test TDX Adapter with raising Memory Error"""
        tdx_adapter = adapter_object()

        def mock_cdll(arg1):
            return None

        def mock_sha512():
            raise MemoryError

        with patch.object(ctypes, "CDLL", new=mock_cdll):
            with patch("ctypes.CDLL") as mock_cdll:
                mock_cdll.return_value.tdx_att_get_quote.return_value = 0
                with patch.object(hashlib, "sha512", new=mock_sha512):
                    evidence = tdx_adapter.collect_evidence("")
                    assert evidence == None

    def test_adpater_runtime_error(self):
        """Test method to test TDX Adapter with raising Runtime Error"""
        tdx_adapter = adapter_object()

        def mock_cdll(arg1):
            return None

        def mock_sha512():
            raise RuntimeError

        with patch.object(ctypes, "CDLL", new=mock_cdll):
            with patch("ctypes.CDLL") as mock_cdll:
                mock_cdll.return_value.tdx_att_get_quote.return_value = 0
                with patch.object(hashlib, "sha512", new=mock_sha512):
                    evidence = tdx_adapter.collect_evidence("")
                    assert evidence == None


if __name__ == "__main__":
    unittest.main()
