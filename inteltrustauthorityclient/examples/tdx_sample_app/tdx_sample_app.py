"""
Copyright (c) 2024 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""

import ctypes
import json
import sys
import os
import base64
from urllib.parse import urlparse
import validators
import uuid
import logging as log
from urllib.parse import urlparse
from inteltrustauthorityclient.resources import logger as logger
from inteltrustauthorityclient.resources import constants as const
from inteltrustauthorityclient.tdx.intel.tdx_adapter import TDXAdapter
from inteltrustauthorityclient.tdx.azure.azure_tdx_adapter import AzureTDXAdapter
from inteltrustauthorityclient.tdx.gcp.gcp_tdx_adapter import GCPTDXAdapter
from inteltrustauthorityclient.connector import config, connector
from inteltrustauthorityclient.base.evidence_adapter import EvidenceAdapter


def main():
    """Sample App to generate evidence, attest the platform and get the token from ITA."""

    # Set logging
    try:
        logger.setup_logging()
    except ValueError as e:
        log.exception(f"Exception while setting up log : {type(e).__name__}: {e}")
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
        retry_max = const.DEFAULT_RETRY_MAX_NUM

    retry_wait_time_min = os.getenv(const.RETRY_WAIT_TIME_MIN_SEC)
    if retry_wait_time_min is None:
        log.debug("ENV_RETRY_WAIT_TIME is not provided. Hence, setting default value.")
        retry_wait_time_min = const.DEFAULT_RETRY_WAIT_MIN_SEC

    retry_wait_time_max = os.getenv(const.RETRY_WAIT_TIME_MAX_SEC)
    if retry_wait_time_max is None:
        log.debug(
            "ENV_RETRY_WAIT_TIME_MAX is not provided. Hence, setting default value."
        )
        retry_wait_time_max = const.DEFAULT_RETRY_WAIT_MAX_SEC

    timeout_second = os.getenv(const.TIMEOUT_SEC)
    if timeout_second is None:
        log.debug("ENV_TIMEOUT_SEC is not provided. Hence, setting default value.")
        timeout_second = const.DEFAULT_TIMEOUT_SEC

    try:
        # Populate config object
        config_obj = config.Config(
            config.RetryConfig(
                int(retry_wait_time_min), int(retry_wait_time_max), int(retry_max), int(timeout_second)
            ),
            trustauthority_base_url,
            trustAuthority_api_url,
            trust_authority_api_key,
        )
    except ValueError as exc:
        log.error(
            f"Value Error in config object creation : {exc}"
        )
        exit(1)

    if config_obj == None:
        log.error("Error in config() instance initialization")
        exit(1)
    ita_connector = connector.ITAConnector(config_obj)
    # Create TDX Adapter
    user_data = "data generated inside tee"
    adapter_type = os.getenv("ADAPTER_TYPE")
    if adapter_type is None:
        log.error("ADAPTER_TYPE is not set.")
        exit(1)
    adapter = None
    if(adapter_type == const.INTEL_TDX_ADAPTER):
        adapter = TDXAdapter(user_data)
    elif(adapter_type == const.AZURE_TDX_ADAPTER):
        adapter = AzureTDXAdapter(user_data)
    elif(adapter_type == const.GCP_TDX_ADAPTER):
        adapter = GCPTDXAdapter(user_data)
    else:
        log.error("Invalid Adapter Type Selected.")
        exit(1)
    if trust_authority_policy_id != None:
        policy_ids = json.loads(trust_authority_policy_id)
        attest_args = connector.AttestArgs(
            adapter, trust_authority_request_id, policy_ids
        )
    else:
        attest_args = connector.AttestArgs(adapter, trust_authority_request_id)
    # Fetch Attestation Token from ITA
    attestation_token = ita_connector.attest(attest_args)
    if attestation_token is None:
        log.error("Attestation Token is not returned.")
        exit(1)
    token = attestation_token.token
    log.info(f"Attestation token : {token}")
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
        log.error(f"Token verification returned exception : {exc}")
    if verified_token != None:
        log.info("Token Verification Successful")
        log.info(f"Verified Attestation Token : {verified_token}")
    else:
        log.info("Token Verification failed")


# main for function call.
if __name__ == "__main__":
    main()
