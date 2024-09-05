"""
Copyright (c) 2024 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""

import unittest
from unittest.mock import patch, MagicMock
import io
import argparse
import json
from io import StringIO
from inteltrustauthorityclient.resources import constants as const
from inteltrustauthorityclient.connector import config, connector
from inteltrustauthorityclient.tdx.tdx_adapter import TDXAdapter
from inteltrustauthorityclient.nvgpu.gpu_adapter import GPUAdapter
from inteltrustauthorityclient.cli import * 


class TestIntelTrustAuthorityCLI(unittest.TestCase):

    def test_cmd_evidence_tdx_with_user_data(self, mock_tdx_adapter):
        args = argparse.Namespace(attest_type='tdx', user_data='user_data', nonce=None)
        mock_tdx_adapter.return_value.collect_evidence.return_value = 'evidence'

        trustauthority-pycli.cmd_evidence(args)

        mock_tdx_adapter.assert_called_once_with('user_data', None)
        mock_tdx_adapter.return_value.collect_evidence.assert_called_once_with(None)
        mock_print.assert_called_once_with('evidence.quote')

    def test_cmd_evidence_tdx_without_user_data(self, mock_tdx_adapter):
        args = argparse.Namespace(attest_type='tdx', user_data=None, nonce='nonce')
        mock_tdx_adapter.return_value.collect_evidence.return_value = 'evidence'

        trustauthority-pycli.cmd_evidence(args)

        mock_tdx_adapter.assert_called_once_with('', None)
        mock_tdx_adapter.return_value.collect_evidence.assert_called_once_with('nonce')
        mock_print.assert_called_once_with('evidence.quote')


    def test_cmd_evidence_nvgpu(self, mock_gpu_adapter):
        args = argparse.Namespace(attest_type='nvgpu', user_data=None, nonce='nonce')
        mock_gpu_adapter.return_value.collect_evidence.return_value = 'evidence'
        
        trustauthority-pycli.cmd_evidence(args)
        
        mock_gpu_adapter.assert_called_once_with()
        mock_gpu_adapter.return_value.collect_evidence.assert_called_once_with('nonce')
        mock_print.assert_called_once_with('evidence.evidence')

    def test_cmd_attest_tdx(self, mock_tdx_adapter, mock_ita_connector, mock_config, mock_log, mock_json_load, mock_open):
        args = MagicMock()
        args.config = 'config.json'
        args.attest_type = 'tdx'
        args.user_data = 'user_data'

        mock_json_load.return_value = {
            'trustauthority_base_url': 'base_url',
            'trustauthority_api_url': 'api_url',
            'trustauthority_api_key': 'api_key',
            'trust_authority_request_id': 'request_id',
            'trust_authority_policy_id': 'policy_id'
        }

        mock_config.return_value = MagicMock()
        mock_tdx_adapter.return_value = MagicMock()
        mock_ita_connector.return_value = MagicMock()
        mock_ita_connector.return_value.attest_composite.return_value = MagicMock(token='token', headers="{'request-id': '123', 'trace-id': '456'}")

        trustauthority-pycli.cmd_attest(args)

        mock_open.assert_called_once_with('config.json', 'r')
        mock_json_load.assert_called_once_with(mock_open().__enter__())
        mock_log.error.assert_not_called()
        mock_config.assert_called_once_with(
            mock_config.RetryConfig(1, 1, 1),
            'base_url',
            'api_url',
            'api_key'
        )
        mock_ita_connector.assert_called_once_with(mock_config())
        mock_tdx_adapter.assert_called_once_with('user_data', None)
        mock_ita_connector().attest_composite.assert_called_once_with(mock_ita_connector.TDXAttestArgs(), None)
        mock_ita_connector().attest_composite().token = 'token'
        self.assertEqual(mock_ita_connector().attest_composite().headers, "{'request-id': '123', 'trace-id': '456'}")

    def test_cmd_attest_nvgpu(self, mock_gpu_adapter, mock_ita_connector, mock_config, mock_log, mock_json_load, mock_open):
        args = MagicMock()
        args.config = 'config.json'
        args.attest_type = 'nvgpu'
        args.user_data = 'user_data'

        mock_json_load.return_value = {
            'trustauthority_base_url': 'base_url',
            'trustauthority_api_url': 'api_url',
            'trustauthority_api_key': 'api_key',
            'trust_authority_request_id': 'request_id',
            'trust_authority_policy_id': 'policy_id'
        }

        mock_config.return_value = MagicMock()
        mock_tdx_adapter.return_value = MagicMock()
        mock_ita_connector.return_value = MagicMock()
        mock_ita_connector.return_value.attest_composite.return_value = MagicMock(token='token', headers="{'request-id': '123', 'trace-id': '456'}")

        trustauthority-pycli.cmd_attest(args)

        mock_open.assert_called_once_with('config.json', 'r')
        mock_json_load.assert_called_once_with(mock_open().__enter__())
        mock_log.error.assert_not_called()
        mock_config.assert_called_once_with(
            mock_config.RetryConfig(1, 1, 1),
            'base_url',
            'api_url',
            'api_key'
        )
        mock_ita_connector.assert_called_once_with(mock_config())
        mock_gpu_adapter.assert_called_once_with('user_data', None)
        mock_ita_connector().attest_composite.assert_called_once_with(None, mock_ita_connector.GPUAttestArgs())
        mock_ita_connector().attest_composite().token = 'token'
        self.assertEqual(mock_ita_connector().attest_composite().headers, "{'request-id': '123', 'trace-id': '456'}")


    def test_cmd_attest_tdx_nvgpu(self, mock_ita_connector, mock_config, mock_json_load, mock_open):
        args = MagicMock()
        args.attest_type = 'tdx+nvgpu'
        args.config = 'config.json'
        args.user_data = 'user_data'

        mock_json_load.return_value = {
            'trustauthority_base_url': 'base_url',
            'trustauthority_api_url': 'api_url',
            'trustauthority_api_key': 'api_key',
            'trust_authority_request_id': 'request_id',
            'trust_authority_policy_id': 'policy_id'
        }

        mock_config.return_value = MagicMock()
        mock_tdx_adapter.return_value = MagicMock()
        mock_gpu_adapter.return_value = MagicMock()
        mock_ita_connector.return_value = MagicMock()
        mock_ita_connector.return_value.attest_composite.return_value = MagicMock(token='token', headers="{'request-id': '123', 'trace-id': '456'}")

        trustauthority-pycli.cmd_attest(args)

        mock_open.assert_called_once_with('config.json', 'r')
        mock_json_load.assert_called_once_with(mock_open().__enter__())
        mock_log.error.assert_not_called()
        mock_config.assert_called_once_with(
            mock_config.RetryConfig(1, 1, 1),
            'base_url',
            'api_url',
            'api_key'
        )
        mock_ita_connector.assert_called_once_with(mock_config())
        mock_tdx_adapter.assert_called_once_with('user_data', None)
        mock_gpu_adapter.assert_called_once_with('user_data', None)
        mock_ita_connector().attest_composite.assert_called_once_with(mock_ita_connector.TDXAttestArgs(), mock_ita_connector.GPUAttestArgs())
        mock_ita_connector().attest_composite().token = 'token'
        self.assertEqual(mock_ita_connector().attest_composite().headers, "{'request-id': '123', 'trace-id': '456'}")

    def test_cmd_verify_success(self, mock_config, mock_exit, mock_open):
        mock_file = StringIO()
        mock_file.write(json.dumps({
            'trustauthority_base_url': 'https://example.com',
            'trustauthority_api_url': 'https://api.example.com',
            'trustauthority_api_key': 'API_KEY'
        }))
        mock_file.seek(0)
        mock_open.return_value = mock_file

        with patch('your_module.config.Config') as mock_config, \
             patch('your_module.connector.ITAConnector') as mock_connector:
            trustauthority-pycli.cmd_verify(['--config', 'config.json', '--token', 'TOKEN'])

            mock_open.assert_called_once_with('config.json', 'r')
            mock_config.assert_called_once_with(
                mock_config.RetryConfig(1, 1, 1),
                'https://example.com',
                'https://api.example.com',
                'API_KEY'
            )
            mock_connector.assert_called_once_with(mock_config.return_value)
            mock_connector.return_value.verify_token.assert_called_once_with('TOKEN')
            self.assertEqual(mock_exit.call_count, 0)

    def test_cmd_verify_missing_config(self, mock_config, mock_exit, mock_open):
        mock_file = StringIO()
        mock_file.write(json.dumps({}))
        mock_file.seek(0)
        mock_open.return_value = mock_file

        trustauthority-pycli.cmd_verify(['--config', 'config.json', '--token', 'TOKEN'])

        mock_open.assert_called_once_with('config.json', 'r')
        mock_exit.assert_called_once_with(1)

    def test_cmd_verify_missing_token(self, mock_config, mock_exit, mock_open):
        mock_file = StringIO()
        mock_file.write(json.dumps({
            'trustauthority_base_url': 'https://example.com',
            'trustauthority_api_url': 'https://api.example.com',
            'trustauthority_api_key': 'API_KEY'
        }))
        mock_file.seek(0)
        mock_open.return_value = mock_file

        trustauthority-pycli.cmd_verify(['--config', 'config.json'])

        mock_open.assert_called_once_with('config.json', 'r')
        mock_exit.assert_called_once_with(1)


if __name__ == '__main__':
    unittest.main()
