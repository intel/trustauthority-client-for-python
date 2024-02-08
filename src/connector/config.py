"""
Copyright (c) 2024 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""

import os
import validators
from urllib.parse import urlparse
from src.resources import constants as constants

class Config:
    def __init__(self, base_url, tls_cfg, api_url, api_key) -> None:
        # self.base_url = base_url if base_url != "" else os.getenv(constants.TRUSTAUTHORITY_BASE_URL)
        base_url_check = base_url if base_url != "" else os.getenv(constants.TRUSTAUTHORITY_BASE_URL)
        if not validate_url(base_url_check):
            raise ValueError("baseurl format not correct")
        self.base_url = base_url_check
        self.tls_cfg = tls_cfg
        api_url_check = api_url if api_url != "" else os.getenv(constants.TRUSTAUTHORITY_API_URL)
        if not validate_url(api_url_check):
            raise ValueError("apiurl format not correct")
        self.api_url = api_url_check
        self.api_key = api_key if api_key != "" else os.getenv(constants.TRUSTAUTHORITY_API_KEY)

    #getter methods
    def base_url(self):
        return self.base_url

    def tls_cfg(self):
        return self.tls_cfg

    def api_url(self):
        return self.api_url

    def api_key(self):
        return self.api_key


class RetryConfig:
    def __init__(self) -> None:
        self.retryWaitTime = os.getenv(constants.RETRY_WAIT_TIME, constants.DEFAULT_RETRY_WAIT_TIME)
        self.retryMax = os.getenv(constants.RETRY_MAX, constants.DEFAULT_RETRY_MAX)

    #getter methods
    def retryWaitTime(self):
        return self.retryWaitTime

    def retryMax(self):
        return self.retryMax


def validate_url(url):
    parsed_url = urlparse(url)
    if(parsed_url.scheme != "https"):
        return False
    return True