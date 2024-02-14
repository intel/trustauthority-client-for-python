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

    trust_authority_policy_id = os.getenv(const.TRUSTAUTHORITY_POLICY_ID)

    request_id = os.getenv(const.TRUSTAUTHORITY_REQUEST_ID)
    # Populate config object
    try:
        config_obj = Config(RetryConfig())
    except Exception as exc:
        log.error(f"Error in config() instance initialization : {exc}")
        exit(1)
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
    token_headers_json = json.loads(attestation_token.headers.replace('\'','\"'))
    log.info("Request id and Trace id are: %s, %s" ,token_headers_json.get("request-id"), token_headers_json.get("trace-id"))
    # verify token- recieved from connector
    try:
        verified_token = ita_connector.verify_token(token)
    except Exception as exc:
        log.error("Token verification returned exception : %s", exc)
    if verified_token != None:
        log.info("Token Verification Successful")
        log.info("Verified Attestation Token : %s",verified_token)
    else:
        log.info("Token Verification failed")


# main for function call.
if __name__ == "__main__":
    main()
