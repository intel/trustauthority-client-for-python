"""
Copyright (c) 2024 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""

import unittest
from unittest.mock import patch, MagicMock
from inteltrustauthorityclient.nvgpu.gpu_adapter import *


def adapter_object():
    """This method initializes TDX Adapter object"""
    return GPUAdapter()


class GPUAdapterTestCase(unittest.TestCase):
    """class TDXAdapterTestCase that inherits from unittest.TestCase"""

    def test_adpater(self):
        """Test method to test TDX Adapter"""
        gpu_adapter = adapter_object()

        def mock_cdll(arg1):
            return None

        evidence = gpu_adapter.collect_evidence("")
        assert evidence != None

    def test_adpater_file_notfound_error(self):
        """Test method to test TDX Adapter with File Not found Error"""
        gpu_adapter = adapter_object()
        evidence = gpu_adapter.collect_evidence()
        assert evidence == None

    def test_adpater_Exception(self):
        """Test method to test TDX Adapter with raising mock Exception"""
        tdx_adapter = adapter_object()
        evidence = tdx_adapter.collect_evidence("")
        assert evidence == None
    
if __name__ == "__main__":
    unittest.main()
