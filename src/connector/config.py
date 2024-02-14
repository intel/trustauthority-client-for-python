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
    """This class creates config object with ITA attributes i.e base url, api url, api key and
    instance of retry config class to be used in creating connector object"""

    def __init__(self, base_url, retry_cfg, api_url, api_key) -> None:
        """Initialises config object

        Args:
            base_url: ITA base url
            retry_cfg: Instance of RetryConfig class
            api_url: ITA api url
            api_key: ITA api key
        """

        base_url_check = (
            base_url if base_url != "" else os.getenv(constants.TRUSTAUTHORITY_BASE_URL)
        )
        if not validate_url(base_url_check):
            raise ValueError("baseurl format not correct")
        self.base_url = base_url_check
        self.retry_cfg = retry_cfg
        api_url_check = (
            api_url if api_url != "" else os.getenv(constants.TRUSTAUTHORITY_API_URL)
        )
        if not validate_url(api_url_check):
            raise ValueError("apiurl format not correct")
        self.api_url = api_url_check
        self.api_key = (
            api_key if api_key != "" else os.getenv(constants.TRUSTAUTHORITY_API_KEY)
        )

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

    def __init__(self) -> None:
        """Initialises Retry config object"""
        self.retry_max = os.getenv(constants.RETRY_MAX)
        if self.retry_max is None:
            log.debug("ENV_RETRY_MAX is not provided. Hence, setting default value.")
            self.retry_max = constants.DEFAULT_RETRY_MAX
        self.retry_wait_time = os.getenv(constants.RETRY_WAIT_TIME)
        if self.retry_wait_time is None:
            log.debug(
                "ENV_RETRY_WAIT_TIME is not provided. Hence, setting default value."
            )
        self.retry_wait_time = constants.DEFAULT_RETRY_WAIT_TIME

    # getter methods
    def retry_wait_time(self):
        return self.retry_wait_time

    def retry_max(self):
        return self.retry_max


def validate_url(url):
    parsed_url = urlparse(url)
    if parsed_url.scheme != "https":
        return False
    return True
