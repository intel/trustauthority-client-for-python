"""
Copyright (c) 2024 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""

import os
import validators
import logging as log
from urllib.parse import urlparse
from src.resources import constants as constants
from src.resources import logging as logger


class Config:
    """This class creates config object with Intel Trust Authority attributes i.e base url, api url, api key and
    instance of retry config class to be used in creating connector object"""

    def __init__(self, retry_cfg, base_url, api_url, api_key) -> None:
        """Initialises config object

        Args:
            base_url: Intel Trust Authority base url
            retry_cfg: Instance of RetryConfig class
            api_url: Intel Trust Authority api url
            api_key: Intel Trust Authority api key
        """
        if not validate_url(base_url):
            log.error("validate_url() failed for Intel Trust Authority Base URL")
            return None
        self.base_url = base_url
        if not validate_url(api_url):
            log.error("validate_url() failed for Intel Trust Authority API URL")
            return None
        self.api_url = api_url
        self.retry_cfg = retry_cfg
        self.api_key = api_key

    # getter methods
    def base_url(self):
        return self.base_url

    def retry_cfg(self):
        return self.retry_cfg

    def api_url(self):
        return self.api_url

    def api_key(self):
        return self.api_key


class RetryConfig:
    """This class creates Retry Config object with retry max and retry wait time attributes"""

    def __init__(self, retry_max, retry_wait_time) -> None:
        """Initialises Retry config object"""
        self.retry_max = retry_max
        self.retry_wait_time = retry_wait_time

    # getter methods
    def retry_wait_time(self):
        return self.retry_wait_time

    def retry_max(self):
        return self.retry_max


def validate_url(url):
    parsed_url = validators.url(url)
    if parsed_url:
        if urlparse(url).scheme != "https":
            log.error("URL scheme has to https")
            return False
        return True
    return False
