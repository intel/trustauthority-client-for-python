"""
Copyright (c) 2024 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""

from urllib.parse import urlparse
import validators
import logging as log
from tenacity import wait_exponential
from src.resources import constants as constants


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
            raise ValueError("validate_url() failed for Intel Trust Authority Base URL")
        if not validate_url(api_url):
            raise ValueError("validate_url() failed for Intel Trust Authority API URL")
        self.base_url = base_url
        self.api_url = api_url
        self.retry_cfg = retry_cfg
        self.api_key = api_key

    # getter methods
    def get_base_url(self):
        return self.base_url

    def get_retry_cfg(self):
        return self.retry_cfg

    def get_api_url(self):
        return self.api_url

    def get_api_key(self):
        return self.api_key


class RetryConfig:
    """This class creates Retry Config object with retry max and retry wait time attributes"""

    def __init__(
        self,
        retry_wait_min: int,
        retry_wait_max: int,
        retry_max_num: int,
        check_retry=None,
        backoff=None,
    ) -> None:
        """Initialises Retry config object"""
        self.retry_wait_min_sec = (
            retry_wait_min
            if retry_wait_min != 0
            else constants.DEFAULT_RETRY_WAIT_MIN_SEC
        )
        self.retry_wait_max_sec = (
            retry_wait_max
            if retry_wait_max != 0
            else constants.DEFAULT_RETRY_WAIT_MAX_SEC
        )
        self.retry_max_num = (
            retry_max_num if retry_max_num != 0 else constants.DEFAULT_RETRY_MAX_NUM
        )
        self.backoff = (
            backoff
            if backoff != None
            else wait_exponential(
                multiplier=1, min=self.retry_wait_min_sec, max=self.retry_wait_max_sec
            )
        )
        self.check_retry = check_retry if check_retry != None else self.retry_policy

    def retry_policy(self, status_code):
        retryable_status_code = (500, 503, 504)
        return status_code in retryable_status_code


def validate_url(url):
    parsed_url = validators.url(url)
    if parsed_url:
        if urlparse(url).scheme != "https":
            log.error("URL scheme has to https")
            return False
        return True
    return False
