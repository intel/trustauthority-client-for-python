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
        self.assertEqual(retryconfig_obj.timeout_sec, 2)

    def test_retry_config_default_values(self):
        """Test method to test RetryConfig object initialization with custom values"""
        retryconfig_obj = RetryConfig(0, 0, 0)
        self.assertEqual(retryconfig_obj.retry_wait_min_sec, 2)
        self.assertEqual(retryconfig_obj.retry_wait_max_sec, 2)
        self.assertEqual(retryconfig_obj.retry_max_num, 2)
        self.assertEqual(retryconfig_obj.timeout_sec, 30)

    def test_retry_config_retry_policy(self):
        """Test method to test RetryConfig retry_policy method"""
        retryconfig_obj = RetryConfig(2, 5, 3)
        self.assertTrue(retryconfig_obj.retry_policy(500))
        self.assertTrue(retryconfig_obj.retry_policy(503))
        self.assertTrue(retryconfig_obj.retry_policy(504))
        self.assertFalse(retryconfig_obj.retry_policy(200))
        self.assertFalse(retryconfig_obj.retry_policy(404))
        self.assertFalse(retryconfig_obj.retry_policy(502))

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
        self.assertEqual(config_obj.retry_cfg.timeout_sec, 2)

    def test_config_default_timeout(self):
        """Test method to test config object initialisation with default timeout setting"""
        config_obj = Config(
            RetryConfig(2, 2, 2),
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
        self.assertEqual(config_obj.retry_cfg.timeout_sec, 30)

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

    def test_config_invalid_policyID(self):
        """Test method to test config object initialisation with Invalid PolicyID"""
        uuid_str = "invalid-uuid"
        self.assertFalse(validate_uuid(uuid_str))

    def test_config_valid_policyID(self):
        """Test method to test config object initialisation with Invalid PolicyID"""
        uuid_str = "123e4567-e89b-12d3-a456-426614174000"
        self.assertTrue(validate_uuid(uuid_str))

    def test_config_invalid_requestID(self):
        """Test method to test config object initialisation with Invalid API URL"""
        request_id = "@1234"
        self.assertFalse(validate_requestid(request_id))

    def test_config_valid_requestID(self):
        """Test method to test config object initialisation with Invalid API URL"""
        request_id = "1234"
        self.assertTrue(validate_requestid(request_id))


if __name__ == "__main__":
    unittest.main()
