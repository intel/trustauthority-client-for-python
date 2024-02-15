"""
Copyright (c) 2024 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""

import ctypes
import sys
import os
import base64
import re
import uuid
import logging as log
from src.resources import logging as logger
from src.resources import constants as const
from src.tdx.tdx_adapter import TDXAdapter
from src.connector.config import *
from src.connector.connector import *


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

    retry_max = os.getenv(const.RETRY_MAX)
    if retry_max is None:
        log.debug("ENV_RETRY_MAX is not provided. Hence, setting default value.")
        retry_max = const.DEFAULT_RETRY_MAX

    retry_wait_time = os.getenv(const.RETRY_WAIT_TIME)
    if retry_wait_time is None:
        log.debug("ENV_RETRY_WAIT_TIME is not provided. Hence, setting default value.")
    retry_wait_time = const.DEFAULT_RETRY_WAIT_TIME

    # Populate config object
    config_obj = Config(
            RetryConfig(retry_max, retry_wait_time),
            trustauthority_base_url,
            trustAuthority_api_url,
            trust_authority_api_key,
        )
    if config_obj == None:
        log.error("Error in config() instance initialization")
        exit(1)
    ita_connector = ITAConnector(config_obj)
    # Create TDX Adapter
    user_data = "data generated inside tee"
    adapter = TDXAdapter(user_data)
    if trust_authority_policy_id != None:
        policy_ids = json.loads(trust_authority_policy_id)
        attest_args = AttestArgs(adapter, trust_authority_request_id, policy_ids)
    else:
        attest_args = AttestArgs(adapter, trust_authority_request_id)
    # Fetch Attestation Token from ITA
    attestation_token = ita_connector.attest(attest_args)
    if attestation_token is None:
        log.error("Attestation Token is not returned.")
        exit(1)
    token = attestation_token.token
    log.info("Attestation token : %s", token)
    token_headers_json = json.loads(attestation_token.headers.replace("'", '"'))
    log.info(
        "Request id and Trace id are: %s, %s",
        token_headers_json.get("request-id"),
        token_headers_json.get("trace-id"),
    )
    # verify token- recieved from connector
    try:
        verified_token = ita_connector.verify_token(token)
    except Exception as exc:
        log.error("Token verification returned exception : %s", exc)
    if verified_token != None:
        log.info("Token Verification Successful")
        log.info("Verified Attestation Token : %s", verified_token)
    else:
        log.info("Token Verification failed")


# main for function call.
if __name__ == "__main__":
    main()
