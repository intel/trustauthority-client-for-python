"""
Copyright (c) 2024 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""

import unittest
from unittest.mock import patch, MagicMock
from src.tdx.intel.tdx_adapter import *


def intel_tdx_adapter_object():
    """This method initializes Intel TDX Adapter object"""
    return TDXAdapter()

def azure_tdx_adapter_object():
    """This method initializes Azure TDX Adapter object"""
    return AzureTDXAdapter()

class TDXAdapterTestCase(unittest.TestCase):
    """class TDXAdapterTestCase that inherits from unittest.TestCase"""

    def test_intel_tdx_adpater(self):
        """Test method to test TDX Adapter"""
        tdx_adapter = intel_tdx_adapter_object()

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

    def test_intel_tdx_adpater_file_notfound_error(self):
        """Test method to test TDX Adapter with File Not found Error"""
        tdx_adapter = intel_tdx_adapter_object()
        evidence = tdx_adapter.collect_evidence()
        assert evidence == None

    def test_intel_tdx_adpater_dcap_load_error(self):
        """Test method to test TDX Adapter with raising Dcap Load Error"""
        tdx_adapter = intel_tdx_adapter_object()

        def mock_cdll(arg1):
            raise OSError("Error in loading library")

        with patch.object(ctypes, "CDLL", new=mock_cdll):
            evidence = tdx_adapter.collect_evidence()
            assert evidence == None

    def test_intel_tdx_adapter_free_quote_error(self):
        """Test method to test TDX Adapter with raising freeing quote error"""
        tdx_adapter = intel_tdx_adapter_object()
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

    def test_intel_tdx_adpater_memory_error(self):
        """Test method to test TDX Adapter with raising Memory Error"""
        tdx_adapter = intel_tdx_adapter_object()

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

    def test_intel_tdx_adpater_runtime_error(self):
        """Test method to test TDX Adapter with raising Runtime Error"""
        tdx_adapter = intel_tdx_adapter_object()

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

    def test_azure_tdx_adpater(self):
        """Test method to test Azure TDX Adapter"""
        tdx_adapter = adapter_object()

        class mock_class:
            def __init__(self,stdout) -> None:
                self.stdout = stdout
        def mock_subprocess_run(*args, **kwargs):
            return mock_class(b"abaghalsmolamskakakKaaa")
        with patch("hashlib.sha512") as mock_sha_hash:
            mock_sha_hash.update = None
            mock_sha_hash.digest = None
            with patch.object(subprocess, "run", new=mock_subprocess_run):
                with patch("tempfile.NamedTemporaryFile") as mock_tempfile:
                    mock_tempfile.return_value.name = "mock"
                    with patch("requests.post", url="http://169.254.169.254/acc/tdquote") as mock_post_request:
                        mocked_response = MagicMock()
                        mocked_response.json.return_value = {"quote":"wwwwwww"}
                        mock_post_request.return_value = mocked_response
                        with patch("struct.unpack") as mock_unpack:
                            mock_unpack.return_value = [1]
                            evidence = tdx_adapter.collect_evidence("")
                            assert evidence != None

    def test_azure_tdx_adpater_subprocess_calledprocesserror(self):
        """Test method to test Azure TDX Adapter with raising called process Error"""
        tdx_adapter = adapter_object()

        def mock_subprocess_run(*args, **kwargs):
            raise subprocess.CalledProcessError(cmd = "",returncode=1, output="Mock Error")
        
        with patch("hashlib.sha512") as mock_sha_hash:
            mock_sha_hash.update = None
            mock_sha_hash.digest = None
            with patch.object(subprocess, "run", new=mock_subprocess_run):
                evidence = tdx_adapter.collect_evidence("")
                assert evidence == None
    
    def test_azure_tdx_adpater_subprocess_Exception(self):
        """Test method to test Azure TDX Adapter with raising subprocess Exception"""
        tdx_adapter = adapter_object()

        def mock_subprocess_run(*args, **kwargs):
            raise Exception("Mock Exception")
        
        with patch("hashlib.sha512") as mock_sha_hash:
            mock_sha_hash.update = None
            mock_sha_hash.digest = None
            with patch.object(subprocess, "run", new=mock_subprocess_run):
                evidence = tdx_adapter.collect_evidence("")
                assert evidence == None

    # def test_azure_tdxadpater(self):
    #     """Test method to test TDX Adapter"""
    #     tdx_adapter = adapter_object()

    #     class mock_class:
    #         def __init__(self,stdout) -> None:
    #             self.stdout = stdout
    #     def mock_subprocess_run(*args, **kwargs):
    #         return mock_class(b"abaghalsmolamskakakKaaa")
    #     def mock_subprocess_run1(*args, **kwargs):
    #         raise Exception("Mock Exceptions")
    #     with patch("hashlib.sha512") as mock_sha_hash:
    #         mock_sha_hash.update = None
    #         mock_sha_hash.digest = None
    #         with patch.object(subprocess, "run", new=mock_subprocess_run):
    #             with patch("tempfile.NamedTemporaryFile") as mock_tempfile:
    #                 mock_tempfile.return_value.name = "mock"
    #                 with patch.object(subprocess, "run", new=mock_subprocess_run1):
    #                     evidence = tdx_adapter.collect_evidence("")
    #                     assert evidence != None


if __name__ == "__main__":
    unittest.main()
