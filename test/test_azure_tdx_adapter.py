"""
Copyright (c) 2024 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""

import unittest
from unittest.mock import patch, MagicMock
from inteltrustauthorityclient.tdx.azure.azure_tdx_adapter import *


def adapter_object():
    """This method initializes TDX Adapter object"""
    return AzureTDXAdapter("user_data")


class TDXAdapterTestCase(unittest.TestCase):
    """class TDXAdapterTestCase that inherits from unittest.TestCase"""

    def test_adpater(self):
        """Test method to test Azure TDX Adapter"""
        tdx_adapter = adapter_object()

        class mock_class:
            def __init__(self, stdout) -> None:
                self.stdout = stdout

        def mock_subprocess_run(*args, **kwargs):
            return mock_class(b"abaghalsmolamskakakKaaa")

        with patch("hashlib.sha512") as mock_sha_hash:
            mock_sha_hash.update = None
            mock_sha_hash.digest = None
            with patch.object(subprocess, "run", new=mock_subprocess_run):
                with patch("tempfile.NamedTemporaryFile") as mock_tempfile:
                    mock_tempfile.return_value.name = "mock"
                    with patch(
                        "requests.post", url="http://169.254.169.254/acc/tdquote"
                    ) as mock_post_request:
                        mocked_response = MagicMock()
                        mocked_response.json.return_value = {"quote": "wwwwwww"}
                        mock_post_request.return_value = mocked_response
                        with patch("struct.unpack") as mock_unpack:
                            mock_unpack.return_value = [1]
                            evidence = tdx_adapter.collect_evidence("")
                            assert evidence != None

    def test_adpater_subprocess_calledprocesserror(self):
        """Test method to test Azure TDX Adapter with raising called process Error"""
        tdx_adapter = adapter_object()

        def mock_subprocess_run(*args, **kwargs):
            raise subprocess.CalledProcessError(
                cmd="", returncode=1, output="Mock Error"
            )

        with patch("hashlib.sha512") as mock_sha_hash:
            mock_sha_hash.update = None
            mock_sha_hash.digest = None
            with patch.object(subprocess, "run", new=mock_subprocess_run):
                evidence = tdx_adapter.collect_evidence("")
                assert evidence == None

    def test_adpater_subprocess_Exception(self):
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

    # def test_adpater(self):
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
