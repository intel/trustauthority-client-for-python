"""
Copyright (c) 2024 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""

import unittest
from unittest.mock import patch, MagicMock
from inteltrustauthorityclient.nvgpu.gpu_adapter import GPUAdapter

class GPUAdapterTestCase(unittest.TestCase):

    """class GPUAdapterTestCase that inherits from unittest.TestCase"""
    def test_collect_evidence_with_nonce(self):
        gpu_adapter = GPUAdapter()
        nonce = "1234567890abcdef"

        with patch("inteltrustauthorityclient.nvgpu.gpu_adapter.attest_gpu_remote.generate_evidence") as mock_generate_evidence: 
            mock_generate_evidence.return_value = [{"attestationReportHexStr": "report", "certChainBase64Encoded": "cert_chain"}]
            result = gpu_adapter.collect_evidence(nonce)
            mock_generate_evidence.assert_called_once_with(nonce)
            self.assertIsNotNone(result)
 
    def test_collect_evidence_without_nonce(self):
        gpu_adapter = GPUAdapter()
        nonce = ""
 
        with patch("inteltrustauthorityclient.nvgpu.gpu_adapter.attest_gpu_remote.generate_evidence") as mock_generate_evidence: 
            mock_generate_evidence.return_value = [{"attestationReportHexStr": "report", "certChainBase64Encoded": "cert_chain"}]
            result = gpu_adapter.collect_evidence(nonce)
            mock_generate_evidence.assert_called_once_with(nonce)
            self.assertIsNotNone(result)
 
    def test_collect_evidence_exception(self):
        gpu_adapter = GPUAdapter()
        nonce = "1234567890abcdef"
 
        with patch("inteltrustauthorityclient.nvgpu.gpu_adapter.attest_gpu_remote.generate_evidence") as mock_generate_evidence: 
            mock_generate_evidence.side_effect = Exception("Mock Exception")
            result = gpu_adapter.collect_evidence(nonce)
            mock_generate_evidence.assert_called_once_with(nonce)
            self.assertIsNone(result)
 
    def test_build_payload(self):
        gpu_adapter = GPUAdapter()
        nonce = "1234567890abcdef"
        evidence = "evidence"
        cert_chain = "cert_chain"
        expected_payload = '{"nonce": "1234567890abcdef", "evidence": "ZXZpZGVuY2U=", "arch": "HOPPER", "certificate": "cert_chain"}'
 
        result = gpu_adapter.build_payload(nonce, evidence, cert_chain)
        self.assertEqual(result, expected_payload)
 
    def test_build_payload_exception(self):
        gpu_adapter = GPUAdapter()
        nonce = "1234567890abcdef"
        evidence = "evidence"
        cert_chain = "cert_chain"
 
        with patch("json.dumps") as mock_json_dumps:
            mock_json_dumps.side_effect = TypeError("Mock Exception")
            result = gpu_adapter.build_payload(nonce, evidence, cert_chain)
            self.assertIsNone(result)
            mock_json_dumps.assert_called_once_with({"nonce": "1234567890abcdef", "evidence": "ZXZpZGVuY2U=", "arch": "HOPPER", "certificate": "cert_chain"})
 
if __name__ == "__main__":
    unittest.main()
