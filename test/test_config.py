"""
Copyright (c) 2024 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""

import unittest
from inteltrustauthorityclient.connector.config import *


class ConfigTestCase(unittest.TestCase):
    """class ConfigTestCase that inherits from unittest.TestCase"""

    def test_retry_config(self):
        """Test method to test retry config object initialisation"""
        retryconfig_obj = RetryConfig(2, 2, 2, 2)
        self.assertEqual(retryconfig_obj.retry_wait_min_sec, 2)
        self.assertEqual(retryconfig_obj.retry_wait_max_sec, 2)
        self.assertEqual(retryconfig_obj.retry_max_num, 2)

    def test_config(self):
        """Test method to test config object initialisation"""
        config_obj = Config(
            RetryConfig(2, 2, 2, 2),
            "https://custom-base-url-ITA.com",
            "https://custom-api-url-ITA.com",
            "apikey",
        )
        self.assertEqual(config_obj.api_key, "apikey")
        self.assertEqual(config_obj.api_url, "https://custom-api-url-ITA.com")
        self.assertEqual(config_obj.base_url, "https://custom-base-url-ITA.com")
        self.assertEqual(config_obj.retry_cfg.retry_wait_min_sec, 2)
        self.assertEqual(config_obj.retry_cfg.retry_wait_max_sec, 2)
        self.assertEqual(config_obj.retry_cfg.retry_max_num, 2)

    def test_config_invalid_baseurl(self):
        """Test method to test config object initialisation with Invalid Base URL"""
        with self.assertRaises(ValueError):
            config_obj = Config(
                RetryConfig(2, 2, 2, 2),
                "httpa://custom-base-url-ITA.com",
                "https://custom-api-url-ITA.com",
                "apikey",
            )

    def test_config_invalid_apiurl(self):
        """Test method to test config object initialisation with Invalid API URL"""
        with self.assertRaises(ValueError):
            config_obj = Config(
                RetryConfig(2, 2, 2, 2),
                "https://custom-base-url-ITA.com",
                "httpa://custom-api-url-ITA.com",
                "apikey",
            )


if __name__ == "__main__":
    unittest.main()
