"""
Copyright (c) 2024 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""

import ctypes
import sys
import os
import base64
import logging as log
from src.resources import logging as logger
from src.resources import constants as const
from src.tdx.tdx_adapter import TDXAdapter


def main():
    """Sample App to generate evidence, attest the platform and get the token from ITA."""

    # Set logging
    try:
        logger.setup_logging()
    except ValueError as e:
        print("Exception: {type(e).__name__}: {e}")
        log.exception("Exception while setting up log: {e}")
        exit(1)

    # get all the environment variables
    trustauthority_base_url = os.getenv(const.TRUSTAUTHORITY_BASE_URL)
    if trustauthority_base_url is None:
        log.error("ENV_TRUSTAUTHORITY_BASE_URL is not set.")
        exit(1)

    trustAuthority_api_url = os.getenv(const.TRUSTAUTHORITY_API_URL)
    if trustAuthority_api_url is None:
        log.error("ENV_TRUSTAUTHORITY_API_URL is not set.")
        exit(1)

    trust_authority_api_key = os.getenv(const.TRUSTAUTHORITY_API_KEY)
    if trust_authority_api_key is None:
        log.error("ENV_TRUSTAUTHORITY_API_KEY is not set.")
        exit(1)

    trust_authority_request_id = os.getenv(const.TRUSTAUTHORITY_REQUEST_ID)

    trust_authority_policy_id = os.getenv(const.TRUSTAUTHORITY_POLICY_ID)
    if trust_authority_policy_id is None:
        log.error("ENV_TRUSTAUTHORITY_POLICY_ID is not set.")
        exit(1)

    retry_max = os.getenv(const.RETRY_MAX)
    if retry_max is None:
        log.debug("ENV_RETRY_MAX is not provided. Hence, setting default value.")
        retry_max = const.DEFAULT_RETRY_MAX

    retry_wait_time = os.getenv(const.RETRY_WAIT_TIME)
    if retry_wait_time is None:
        log.debug("ENV_RETRY_WAIT_TIME is not provided. Hence, setting default value.")
    retry_wait_time = const.DEFAULT_RETRY_WAIT_TIME

    
    # Populate config object
    # Create TDX Adapter
    user_data = "data generated inside tee"
    adapter = TDXAdapter(user_data, None)
    # Fetch TDX Quote
    # nonce = b"cVd1K1gxaFNwU05JbkMvYkpHOERHRWF0TkJRbGxicmpieDBrRUtFeFRPNVJRUVp5Rm9BbFdKQTYxMDVTZGpXaWxRLzZEL0RhSmRPRHdiRFF6cXBDeEE9PQ==" + b"MjAyNC0wMS0zMSAxMTowODoxMSArMDAwMCBVVEM="
    evidence = adapter.collect_evidence()
    if evidence is None:
        log.error("Evidence is not returned.")
        exit(1)
    # Convert to base64 encoded
    base64_encoded_quote = base64.b64encode(evidence.quote).decode("utf-8")
    log.info("Quote value: ".base64_encoded_quote)
    # call connector with config object
    # call attest in connector
    # Print request_id and trace_id
    # Print token
    # verify token- recieved from connector


# main for function call.
if __name__ == "__main__":
    main()