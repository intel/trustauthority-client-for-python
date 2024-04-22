"""
Copyright (c) 2024 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""

import unittest
from unittest.mock import patch, MagicMock
from inteltrustauthorityclient.sgx.intel.sgx_adapter import *


def adapter_object():
    """This method initializes TDX Adapter object"""
    mock_report_function = lambda *args, **kwargs: 0
    return SGXAdapter("eid", mock_report_function, "user_data")


class SGXAdapterTestCase(unittest.TestCase):
    """class TDXAdapterTestCase that inherits from unittest.TestCase"""

    def test_adpater(self):
        """Test method to test SGX Adapter"""
        sgx_adapter = adapter_object() 
        with patch.object(ctypes, "CDLL") as mock_cdll:
            mock_cdll.return_value = None
            with patch("ctypes.CDLL") as mock_cdll:
                mock_cdll.return_value.sgx_qe_get_target_info.return_value = 0
                with patch("ctypes.create_string_buffer") as  mock_string_buffer:
                    mock_string_buffer.return_value = b"mock_string_buffer"
                    mock_cdll.return_value.sgx_qe_get_quote_size.return_value = 0
                    mock_cdll.return_value.sgx_qe_get_quote.return_value = 0
                    with patch("base64.b64encode") as mock_encode:
                        mock_encode.return_value = b'SGVsbG8sIFdvcmxkIQ=='
                        evidence = sgx_adapter.collect_evidence("nonce")
                        assert evidence is not None

    def test_adpater_cdll_os_error(self):
        """Test method to test SGX Adapter with raising OS Error while loading dcap library"""
        sgx_adapter = adapter_object() 
        def mock_cdll(arg1):
            raise OSError("mock os error")
        with patch.object(ctypes, "CDLL", new = mock_cdll):
            # mock_cdll.return_value = OSError("mock os error")
            evidence = sgx_adapter.collect_evidence("nonce")
            assert evidence is None
    
    def test_adpater_cdll_exception(self):
        """Test method to test SGX Adapter with raising Exception while loading dcap library"""
        sgx_adapter = adapter_object() 
        def mock_cdll(arg1):
            raise Exception("mock Exception")
        with patch.object(ctypes, "CDLL", new = mock_cdll):
            # mock_cdll.return_value = OSError("mock os error")
            evidence = sgx_adapter.collect_evidence("nonce")
            assert evidence is None
                          
    def test_adpater_get_target_info(self):
        """Test method to test sgx_qe_get_target_info function"""
        sgx_adapter = adapter_object() 
        with patch.object(ctypes, "CDLL") as mock_cdll:
            mock_cdll.return_value = None
            with patch("ctypes.CDLL") as mock_cdll:
                mock_cdll.return_value.sgx_qe_get_target_info.return_value = 1
                with self.assertRaises(RuntimeError):
                    evidence = sgx_adapter.collect_evidence("nonce")

    def test_adpater_report_function(self):
        """Test method to test SGX Adapter Report Function"""
        mock_report_function = lambda *args, **kwargs: 1
        sgx_adapter = SGXAdapter("eid", mock_report_function, "user_data")
        with patch.object(ctypes, "CDLL") as mock_cdll:
            mock_cdll.return_value = None
            with patch("ctypes.CDLL") as mock_cdll:
                mock_cdll.return_value.sgx_qe_get_target_info.return_value = 0
                with patch("ctypes.create_string_buffer") as  mock_string_buffer:
                    mock_string_buffer.return_value = b"mock_string_buffer"
                    with self.assertRaises(RuntimeError):
                        evidence = sgx_adapter.collect_evidence("nonce")

    def test_adpater_get_quote_size_function(self):
        """Test method to test SGX Adapter sgx_qe_get_quote_size Function"""
        sgx_adapter = adapter_object()
        with patch.object(ctypes, "CDLL") as mock_cdll:
            mock_cdll.return_value = None
            with patch("ctypes.CDLL") as mock_cdll:
                mock_cdll.return_value.sgx_qe_get_target_info.return_value = 0
                with patch("ctypes.create_string_buffer") as  mock_string_buffer:
                    mock_string_buffer.return_value = b"mock_string_buffer"
                    mock_cdll.return_value.sgx_qe_get_quote_size.return_value = 1
                    with self.assertRaises(RuntimeError):
                        evidence = sgx_adapter.collect_evidence("nonce")

    def test_adpater_get_quote_function(self):
        """Test method to test SGX Adapter sgx_qe_get_quote Function"""
        sgx_adapter = adapter_object()
        with patch.object(ctypes, "CDLL") as mock_cdll:
            mock_cdll.return_value = None
            with patch("ctypes.CDLL") as mock_cdll:
                mock_cdll.return_value.sgx_qe_get_target_info.return_value = 0
                with patch("ctypes.create_string_buffer") as  mock_string_buffer:
                    mock_string_buffer.return_value = b"mock_string_buffer"
                    mock_cdll.return_value.sgx_qe_get_quote_size.return_value = 0
                    mock_cdll.return_value.sgx_qe_get_quote.return_value = 1
                    with self.assertRaises(RuntimeError):
                        evidence = sgx_adapter.collect_evidence("nonce")

    def test_adpater_base64_b64encode(self):
        """Test method to test SGX Adapter base64.b64encode Function with unencoded string buffer"""
        sgx_adapter = adapter_object() 
        with patch.object(ctypes, "CDLL") as mock_cdll:
            mock_cdll.return_value = None
            with patch("ctypes.CDLL") as mock_cdll:
                mock_cdll.return_value.sgx_qe_get_target_info.return_value = 0
                with patch("ctypes.create_string_buffer") as  mock_string_buffer:
                    mock_string_buffer.return_value = "mock_string_buffer_without_encoding"
                    mock_cdll.return_value.sgx_qe_get_quote_size.return_value = 0
                    mock_cdll.return_value.sgx_qe_get_quote.return_value = 0
                    evidence = sgx_adapter.collect_evidence("nonce")
                    assert evidence is None
                        
if __name__ == "__main__":
    unittest.main()
