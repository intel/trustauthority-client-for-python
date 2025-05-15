"""
Copyright (c) 2024 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""

import json
import os
import uuid
import logging as log
from inteltrustauthorityclient.resources import logger as logger
from inteltrustauthorityclient.resources import constants as const
from inteltrustauthorityclient.tdx.tdx_adapter import TDXAdapter
from inteltrustauthorityclient.tdx.azure.azure_tdx_adapter import AzureTDXAdapter
from inteltrustauthorityclient.connector import config, connector
from inteltrustauthorityclient.base.evidence_adapter import EvidenceAdapter
from inteltrustauthorityclient.connector.evidence import EvidenceType


def main():
    """Sample App to generate evidence, attest the platform and get the token from ITA."""

    # Set logging
    try:
        logger.setup_logging()
    except ValueError as e:
        log.exception(f"Exception while setting up log : {type(e).__name__}: {e}")
        exit(1)

    # get all the environment variables
    trustauthority_base_url = os.getenv("TRUSTAUTHORITY_BASE_URL")
    if trustauthority_base_url is None or trustauthority_base_url == "":
        log.error("TRUSTAUTHORITY_BASE_URL is not set.")
        exit(1)

    trustAuthority_api_url = os.getenv("TRUSTAUTHORITY_API_URL")
    if trustAuthority_api_url is None or trustAuthority_api_url == "":
        log.error("TRUSTAUTHORITY_API_URL is not set.")
        exit(1)

    trust_authority_api_key = os.getenv("TRUSTAUTHORITY_API_KEY")
    if trust_authority_api_key is None or trust_authority_api_key == "":
        log.error("TRUSTAUTHORITY_API_KEY is not set.")
        exit(1)

    trust_authority_request_id = os.getenv("TRUSTAUTHORITY_REQUEST_ID")
    if trust_authority_request_id and not config.validate_requestid(trust_authority_request_id):
        log.error(f"Invalid Request ID: {trust_authority_request_id}")
        exit(1)

    policy_ids = []
    trust_authority_policy_id = os.getenv("TRUSTAUTHORITY_POLICY_ID")
    if trust_authority_policy_id != None:
        policy_ids = json.loads(trust_authority_policy_id)
        if len(policy_ids) > const.POLICY_IDS_MAX_LEN:
            log.error("policy count in request must be between 1 - 10")
            exit(1)
        for uuid_str in policy_ids:
            if not config.validate_uuid(uuid_str):
                log.error(f"Invalid policy UUID: \"{uuid_str}\"")
                exit(1)

    retry_max = os.getenv("RETRY_MAX")
    if retry_max is None:
        log.debug("RETRY_MAX is not provided. Hence, setting default value.")
        retry_max = const.DEFAULT_RETRY_MAX_NUM
    else:
        if not retry_max.isnumeric():
            log.error("Invalid RETRY_MAX format: RETRY_MAX must be an Integer.")
            exit(1)

    retry_wait_time_min = os.getenv("RETRY_WAIT_TIME_MIN")
    if retry_wait_time_min is None:
        log.debug("RETRY_WAIT_TIME is not provided. Hence, setting default value.")
        retry_wait_time_min = const.DEFAULT_RETRY_WAIT_MIN_SEC
    else:
        if not retry_wait_time_min.isnumeric():
            log.error(
                "Invalid RETRY_WAIT_TIME_MIN format: RETRY_WAIT_TIME_MIN must be an Integer."
            )
            exit(1)

    retry_wait_time_max = os.getenv("RETRY_WAIT_TIME_MAX")
    if retry_wait_time_max is None:
        log.debug("RETRY_WAIT_TIME_MAX is not provided. Hence, setting default value.")
        retry_wait_time_max = const.DEFAULT_RETRY_WAIT_MAX_SEC
    else:
        if not retry_wait_time_max.isnumeric():
            log.error(
                "Invalid RETRY_WAIT_TIME_MAX format: RETRY_WAIT_TIME_MAX must be an Integer."
            )
            exit(1)

    timeout_second = os.getenv("CLIENT_TIMEOUT_SEC")
    if timeout_second is None:
        log.debug(
            "CLIENT_TIMEOUT_SEC is not provided. Hence, setting to default value."
        )
        timeout_second = const.DEFAULT_CLIENT_TIMEOUT_SEC

    token_signing_algorithm = os.getenv("TOKEN_SIGNING_ALGORITHM")
    policy_must_match = os.getenv("POLICY_MUST_MATCH")
    if policy_must_match is not None and policy_must_match.lower() in {"true", "false"}:
        policy_must_match = True if policy_must_match.lower() == "true" else False

    try:
        # Populate config object
        config_obj = config.Config(
            config.RetryConfig(
                int(retry_wait_time_min),
                int(retry_wait_time_max),
                int(retry_max),
                int(timeout_second),
            ),
            trustauthority_base_url,
            trustAuthority_api_url,
            trust_authority_api_key,
        )
    except ValueError as exc:
        log.error(f"Value Error in config object creation : {exc}")
        exit(1)

    if config_obj == None:
        log.error("Error in config() instance initialization")
        exit(1)
    ita_connector = connector.ITAConnector(config_obj)
    # Create TDX Adapter
    user_data = b"data generated inside tee"
    adapter_type = os.getenv("ADAPTER_TYPE")
    if adapter_type is None:
        log.error("ADAPTER_TYPE is not set.")
        exit(1)
    adapter = None
    if adapter_type == str(EvidenceType.TDX):
        adapter = TDXAdapter(user_data)
    elif adapter_type == str(EvidenceType.AZTDX):
        adapter = AzureTDXAdapter(user_data)
    else:
        log.error(f"Invalid Adapter Type Provided: {adapter_type}.")
        exit(1)
    log.debug(f"adapter type: {adapter_type}")
    attest_args = connector.AttestArgs(
        adapter,
        token_signing_algorithm,
        policy_must_match,
        trust_authority_request_id,
        policy_ids,
    )
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
    if verified_token is not None:
        log.info("Token Verification Successful")
        log.info(f"Verified Attestation Token : {verified_token}")
    else:
        log.info("Token Verification failed")


# main for function call.
if __name__ == "__main__":
    main()