"""
Copyright (c) 2024 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""

import unittest
from src.connector.config import *


class ConfigTestCase(unittest.TestCase):
    """class ConfigTestCase that inherits from unittest.TestCase"""
    
    def test_config_invalid_baseurl(self):
        """Test method to test config object initialisation with invalid base url"""
        exception_string=""
        try:
            config_obj = Config("bogus/n/url", RetryConfig(), "https://custom-url/api/v1", "apikey")
        except Exception as exc:
            exception_string = str(exc)
        assert exception_string == "baseurl format not correct"

    def test_config_invalid_apiurl(self):
        """Test method to test config object initialisation with invalid api url"""
        exception_string=""
        try:
            config_obj = Config("https://custom-api-url/api/v1", RetryConfig(), "bogus/apiurl", "apikey")
        except Exception as exc:
            exception_string = str(exc)
        assert exception_string == "apiurl format not correct"

    def test_config(self):
        """Test method to test config object initialisation"""
        exception_string=""
        try:
            config_obj = Config("https://custom-base-url/api/v1", RetryConfig(), "https://custom-api-url/api/v1", "apikey")
        except Exception as exc:
            exception_string = str(exc)
        assert exception_string == ""
    
    def test_retry_config(self):
        """Test method to test retry config object initialisation"""
        retyrconfig_obj = RetryConfig()
        assert retyrconfig_obj.retryMax == 2 and retyrconfig_obj.retryWaitTime == 2


if __name__ == '__main__':
    unittest.main()