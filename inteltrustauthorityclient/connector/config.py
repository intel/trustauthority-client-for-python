"""
Copyright (c) 2024 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""

import re
import binascii
from urllib.parse import urlparse
import uuid
import base64
import validators
import logging as log
from tenacity import wait_exponential
from inteltrustauthorityclient.resources import constants


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
            raise ValueError("Invalid Intel Trust Authority Base URL")
        if not validate_url(api_url):
            raise ValueError("Invalid Intel Trust Authority API URL")
        if not validate_apikey(api_key):
            raise ValueError("Invalid Intel Trust Authority API Key")

        self._base_url = base_url
        self._api_url = api_url
        self._retry_cfg = retry_cfg
        self._api_key = api_key

    @property
    def base_url(self):
        """Getter method."""
        return self._base_url

    @property
    def retry_cfg(self):
        """Getter method."""
        return self._retry_cfg

    @property
    def api_url(self):
        """Getter method."""
        return self._api_url

    @property
    def api_key(self):
        """Getter method."""
        return self._api_key


class RetryConfig:
    """This class creates Retry Config object with retry max and retry wait time attributes"""

    def __init__(
        self,
        retry_wait_min: int = None,
        retry_wait_max: int = None,
        retry_max_num: int = None,
        timeout_sec: int = None,
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
        self.timeout_sec = (
            timeout_sec if timeout_sec != None else constants.DEFAULT_CLIENT_TIMEOUT_SEC
        )

    def retry_policy(self, status_code):
        retryable_status_code = (500, 503, 504)
        return status_code in retryable_status_code


def validate_url(url):
    parsed_url = validators.url(url)
    if parsed_url:
        if urlparse(url).scheme != "https":
            log.error("URL scheme has to be https")
            return False
        return True
    return False


def validate_uuid(uuid_str):
    try:
        uuid.UUID(uuid_str)
        return True
    except ValueError as exc:
        log.error(f"ValueError occurred in UUID check request: {exc}")
        return False
    except TypeError as exc:
        log.error(f"TypeError occurred in UUID check request: {exc}")
        return False


def validate_requestid(req_id):
    # Request ID should be atmost 128 characters long and should contain only alphanumeric characters, _, space, -, ., / or \
    request_id_pattern = r'^[a-zA-Z0-9\s\-_\.\\\/]{1,128}$'
    return bool(re.fullmatch(request_id_pattern, req_id))

def validate_apikey(api_key):
    # api_key has to be a valid base64 encoded string
    try:
        if(api_key != base64.b64encode(base64.b64decode(api_key)).decode()):
            return False
        return True
    except binascii.Error as exc:
        log.error(f"Error in apikey validation :{exc}, API key must be a valid Base64 Encoded string")
