"""
Copyright (c) 2024 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""

import unittest
from src.connector.config import *


class ConfigTestCase(unittest.TestCase):
    """class ConfigTestCase that inherits from unittest.TestCase"""

    def test_retry_config(self):
        """Test method to test retry config object initialisation"""
        retryconfig_obj = RetryConfig(2, 2, 2)
        self.assertEqual(retryconfig_obj.retry_wait_min_sec, 2)
        self.assertEqual(retryconfig_obj.retry_wait_max_sec, 2)
        self.assertEqual(retryconfig_obj.retry_max_num, 2)

    def test_config(self):
        """Test method to test config object initialisation"""
        config_obj = Config(
            RetryConfig(2, 2, 2),
            "https://custom-base-url/api/v1",
            "https://custom-api-url/api/v1",
            "apikey",
        )
        self.assertEqual(config_obj.get_api_key(), "apikey")
        self.assertEqual(config_obj.get_api_url(), "https://custom-api-url/api/v1")
        self.assertEqual(config_obj.get_base_url(), "https://custom-base-url/api/v1")
        self.assertEqual(config_obj.retry_cfg.retry_wait_min_sec, 2)
        self.assertEqual(config_obj.retry_cfg.retry_wait_max_sec, 2)
        self.assertEqual(config_obj.retry_cfg.retry_max_num, 2)


if __name__ == "__main__":
    unittest.main()
