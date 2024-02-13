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

    request_id = os.getenv(const.TRUSTAUTHORITY_REQUEST_ID)
    # Populate config object
    retry_config_obj = RetryConfig()
    try:
        config_obj = Config(
            trustauthority_base_url,
            retry_config_obj,
            trustAuthority_api_url,
            trust_authority_api_key,
        )
    except Exception as exc:
        log.exception(f"Caught Exception in config() instance initialization : {exc}")
    ita_connector = ITAConnector(config_obj)
    # Create TDX Adapter
    user_data = "data generated inside tee"
    adapter = TDXAdapter(user_data)
    if trust_authority_policy_id != None:
        policy_ids = json.loads(trust_authority_policy_id)
        attest_args = AttestArgs(adapter, request_id, policy_ids)
    else:
        attest_args = AttestArgs(adapter, request_id)
    # Fetch Attestation Token from ITA
    attestation_token = ita_connector.attest(attest_args)
    if attestation_token is None:
        log.error("Attestation Token is not returned.")
        exit(1)
    token = attestation_token.token
    log.info("Attestation token : %s", token)
    log.info("Response Headers are: %s", attestation_token.headers)
    # verify token- recieved from connector
    log.info("Token Verification :")
    pub_key = ita_connector.verify_token(token)
    if pub_key != None:
        log.info("Token Verification Successful")
        log.info(pub_key)


# main for function call.
if __name__ == "__main__":
    main()
