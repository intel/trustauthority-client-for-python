"""
Copyright (c) 2024 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""

import unittest
from unittest.mock import patch, MagicMock
from inteltrustauthorityclient.tdx.intel.tdx_adapter import *


def adapter_object():
    """This method initializes TDX Adapter object"""
    return TDXAdapter("user_data")


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

    def test_adapter_free_quote_error(self):
        """Test method to test TDX Adapter with raising freeing quote error"""
        tdx_adapter = adapter_object()
        mock_cdll = MagicMock()
        mock_method_get_quote = MagicMock()
        mock_method_get_quote.argtypes = [
            ctypes.POINTER(tdx_report_data_t),
            ctypes.POINTER(tdx_uuid_t),
            ctypes.c_uint32,
            ctypes.POINTER(tdx_uuid_t),
            ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8)),
            ctypes.POINTER(ctypes.c_uint32),
            ctypes.c_uint32,
        ]
        mock_cdll.tdx_att_get_quote = mock_method_get_quote
        mock_cdll.tdx_att_get_quote.return_value = 0
        mock_method_free_quote = MagicMock()
        mock_cdll.tdx_att_free_quote = mock_method_free_quote
        mock_cdll.tdx_att_free_quote.return_value = 1

        with unittest.mock.patch("ctypes.CDLL", return_value=mock_cdll):
            evidence = tdx_adapter.collect_evidence()
        assert evidence != None

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

    def test_adpater_attribute_error(self):
        """Test method to test TDX Adapter with raising Attribute error"""
        tdx_adapter = adapter_object()

        def mock_cdll(arg1):
            return None

        def mock_sha512():
            raise AttributeError

        with patch.object(ctypes, "CDLL", new=mock_cdll):
            with patch("ctypes.CDLL") as mock_cdll:
                mock_cdll.return_value.tdx_att_get_quote.return_value = 0
                with patch.object(hashlib, "sha512", new=mock_sha512):
                    evidence = tdx_adapter.collect_evidence("")
                    assert evidence == None

    def test_adpater_value_error(self):
        """Test method to test TDX Adapter with raising value Error"""
        tdx_adapter = adapter_object()

        def mock_cdll(arg1):
            return None

        def mock_sha512():
            raise ValueError

        with patch.object(ctypes, "CDLL", new=mock_cdll):
            with patch("ctypes.CDLL") as mock_cdll:
                mock_cdll.return_value.tdx_att_get_quote.return_value = 0
                with patch.object(hashlib, "sha512", new=mock_sha512):
                    evidence = tdx_adapter.collect_evidence("")
                    assert evidence == None

    def test_adpater_Exception(self):
        """Test method to test TDX Adapter with raising mock Exception"""
        tdx_adapter = adapter_object()

        def mock_cdll(arg1):
            return None

        def mock_sha512():
            raise Exception

        with patch.object(ctypes, "CDLL", new=mock_cdll):
            with patch("ctypes.CDLL") as mock_cdll:
                mock_cdll.return_value.tdx_att_get_quote.return_value = 0
                with patch.object(hashlib, "sha512", new=mock_sha512):
                    evidence = tdx_adapter.collect_evidence("")
                    assert evidence == None

    def test_adpater_ctypes_ArguementError(self):
        """Test method to test TDX Adapter with raising ctypes Arguement Error"""
        tdx_adapter = adapter_object()

        def mock_cdll(arg1):
            return None

        def mock_sha512():
            raise ctypes.ArgumentError

        with patch.object(ctypes, "CDLL", new=mock_cdll):
            with patch("ctypes.CDLL") as mock_cdll:
                mock_cdll.return_value.tdx_att_get_quote.return_value = 0
                with patch.object(hashlib, "sha512", new=mock_sha512):
                    evidence = tdx_adapter.collect_evidence("")
                    assert evidence == None


if __name__ == "__main__":
    unittest.main()
