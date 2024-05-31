"""
Copyright (c) 2024 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""
# trustauthority-cli-python v1.0

import argparse
import json
import uuid
import sys
import os
import base64
import hashlib
import secrets
from urllib.parse import urlparse
from dotenv import load_dotenv
from inteltrustauthorityclient.resources import constants as const
from inteltrustauthorityclient.connector import config, connector
from inteltrustauthorityclient.tdx.intel.tdx_adapter import TDXAdapter
from inteltrustauthorityclient.nvgpu.gpu_adapter import GPUAdapter
from inteltrustauthorityclient.connector.evidence import Evidence

def cmd_evidence(args):
    if args.attest_type == 'tdx':
        if args.user_data:
            try:
                user_data_bytes = base64.b64decode(args.user_data)
            except Exception as err:
                print(f"Error while base64 decoding of user data: : {err}")
        else:
            user_data_bytes = b"" 

        if args.nonce:
            try:
                nonce_bytes = base64.b64decode(args.nonce)
            except Exception as err:
                print(f"Error while base64 decoding of nonce: : {err}")
        else:
            nonce_bytes = b"" 

        # eventLogger is not used for Python CLI
        tdx_adapter = TDXAdapter(user_data_bytes, None)
        evidence = tdx_adapter.collect_evidence(nonce_bytes)
        if evidence is None:
            print("TDX Quote is not returned")
        print(f"TDX Quote : {evidence.quote}")

    elif args.attest_type == 'nvgpu':
        gpu_adapter = GPUAdapter()

        if args.nonce:
            try:
                nonce_bytes = base64.b64decode(args.nonce)
                gpu_nonce = hashlib.sha256(nonce_bytes).hexdigest()
            except Exception as err:
                print(f"Error while base64 decoding of nonce: : {err}")
        # if nonce is not provided by a user, GPU Adapter will generate random nonce 
        else:
            gpu_nonce = None

        evidence = gpu_adapter.collect_evidence(gpu_nonce)
        if evidence is None:
            print("GPU Evidence is not returned")
        print(f"GPU evidence : {evidence.evidence}")

def cmd_attest(args):
    # Check if request id is valid
    if args.request_id != None:
       if len(args.request_id) > const.REQUEST_ID_MAX_LEN:
            print("Request ID should be atmost 128 characters long.") 
            exit(1)
       for req_char in args.request_id:
            if req_char != '-' and req_char.isalnum() == False:
                print("Request ID should contain only a-z, A-Z, 0-9, and - (hyphen), Special characters are not allowed.")
                exit(1)
       trust_authority_request_id = args.request_id
    # If request_id is not provided as an argument
    else:
       trust_authority_request_id = "cli12345" 

    # Check if policy uuid is valid and the number of policy counts not exceeded.
    policyIds = []
    if args.policy_ids != None:
       pIds = args.policy_ids.split(",")
       if len(pIds) > const.POLICY_IDS_MAX_LEN:
            print("policy count in request must be between 1 - 10")
            exit(1)
       for pId in pIds:
            try:
               uid = uuid.UUID(pId)
            except ValueError:
                print(f"Invalid policy UUID :{pId}")
                exit(1)
            else:
                policyIds.append(uid)
    # Read ITA Env configuration from json file
    with open(args.config, 'r') as cf:
        cf_dict = json.load(cf)

    trustauthority_base_url = cf_dict['trustauthority_base_url']
    if trustauthority_base_url is None:
        print("TRUSTAUTHORITY_BASE_URL is not set.")
        exit(1)

    trustauthority_api_url = cf_dict['trustauthority_api_url']
    if trustauthority_api_url is None:
        print("TRUSTAUTHORITY_API_URL is not set.")
        exit(1)

    trustauthority_api_key = cf_dict['trustauthority_api_key']
    if trustauthority_api_key is None:
        print("TRUSTAUTHORITY_API_KEY is not set.")
        exit(1)

    cf.close()

    config_obj = config.Config(
            config.RetryConfig(
                int(const.DEFAULT_RETRY_WAIT_MIN_SEC), 
                int(const.DEFAULT_RETRY_WAIT_MAX_SEC), 
                int(const.DEFAULT_RETRY_MAX_NUM),
                int(const.DEFAULT_CLIENT_TIMEOUT_SEC),
            ),
            trustauthority_base_url,
            trustauthority_api_url,
            trustauthority_api_key,
        )

    ita_connector = connector.ITAConnector(config_obj)

    if args.attest_type == 'tdx':
        if args.user_data:
            try:
                user_data_bytes = base64.b64decode(args.user_data)
            except Exception as err:
                print(f"Error while base64 decoding of user data: : {err}")
        else:
            user_data_bytes = b""

        tdx_adapter = TDXAdapter(user_data_bytes, None)
        tdx_attest_args = connector.AttestArgs(tdx_adapter, request_id=trust_authority_request_id, policy_ids=policyIds, token_signing_alg=None, policy_must_match=None)
        attestation_token = ita_connector.attest_v2(tdx_attest_args, None)
        if attestation_token is None:
            print("Attestation Token is not returned.")
            exit(1)

        token = attestation_token.token
        print(f"Attestation token : {token}")

    elif args.attest_type =='nvgpu':
        gpu_adapter = GPUAdapter()
        gpu_attest_args = connector.AttestArgs(gpu_adapter, trust_authority_request_id, policy_ids=None, token_signing_alg=None, policy_must_match=None)
        attestation_token = ita_connector.attest_v2(None, gpu_attest_args)
        if attestation_token is None:
            print("Attestation Token is not returned.")
            exit(1)
        token = attestation_token.token
        print(f"Attestation token : {token}")

    elif args.attest_type =='tdx+nvgpu':
        if args.user_data:
            try:
                user_data_bytes = base64.b64decode(args.user_data)
            except Exception as err:
                print(f"Error while base64 decoding of user data: : {err}")
        else:
            user_data_bytes = b"" 

        # Create TDX Adapter
        tdx_adapter = TDXAdapter(user_data_bytes, None)
        # Create GPU Adapter
        gpu_adapter = GPUAdapter()

        tdx_attest_args = connector.AttestArgs(tdx_adapter, trust_authority_request_id, policyIds)
        # GPU appraisal policy is not supported yet until v2 policy is available. 
        gpu_attest_args = connector.AttestArgs(gpu_adapter, trust_authority_request_id, None)
        attestation_token = ita_connector.attest_v2(tdx_attest_args, gpu_attest_args)
        if attestation_token is None:
            print("Attestation Token is not returned.")
            exit(1)
        token = attestation_token.token
        print(f"Attestation token : {token}")

    else:
        print("Attestation Type %s is unknown.", args.attest_type)
        exit(1)


def cmd_verify(args):
    if args.token == None:
        print("Token is not provided")
        exit(1)

    with open(args.config, 'r') as cf:
        cf_dict = json.load(cf)

    trustauthority_base_url = cf_dict['trustauthority_base_url']
    if trustauthority_base_url is None:
        print("TRUSTAUTHORITY_BASE_URL is not set.")
        exit(1)

    trustauthority_api_url = cf_dict['trustauthority_api_url']
    if trustauthority_api_url is None:
        print("TRUSTAUTHORITY_API_URL is not set.")
        exit(1)

    trustauthority_api_key = cf_dict['trustauthority_api_key']
    if trustauthority_api_key is None:
        print("TRUSTAUTHORITY_API_KEY is not set.")
        exit(1)

    cf.close()

    config_obj = config.Config(
            config.RetryConfig(
                int(const.DEFAULT_RETRY_WAIT_MIN_SEC),
                int(const.DEFAULT_RETRY_WAIT_MAX_SEC),
                int(const.DEFAULT_RETRY_MAX_NUM),
                int(const.DEFAULT_CLIENT_TIMEOUT_SEC),
            ),
            trustauthority_base_url,
            trustauthority_api_url,
            trustauthority_api_key,
        )

    ita_connector = connector.ITAConnector(config_obj)

    try:
        verified_token = ita_connector.verify_token(args.token)
    except Exception as exc:
        verified_token = None
        print(f"Token verification returned exception : {exc}")
    if verified_token != None:
        print("Token Verification Successful")
        print(f"Verified Attestation Token : {verified_token}")
    else:
        print("Token Verification failed")
        exit(1)


def main():
    parser = argparse.ArgumentParser(description='Trust Authority CLI')
    subparsers = parser.add_subparsers(title="Commands", dest="command", help="Command to execute")

    # evidence command
    parser_evidence = subparsers.add_parser("evidence", help="Evidence command")
    parser_evidence.add_argument('-a', '--attest-type', choices=['tdx', 'nvgpu'], required=True, help='Attestation Type selection')
    parser_evidence.add_argument('-n', '--nonce', help='Nonce in base64 encoded format')
    parser_evidence.add_argument('-u', '--user-data', help='User Data in base64 encoded format')
    parser_evidence.set_defaults(func=cmd_evidence)

    # attest command
    parser_attest = subparsers.add_parser("attest", help="Attest command")
    parser_attest.add_argument('-a', '--attest-type', choices=['tdx', 'nvgpu', 'tdx+nvgpu'], required=True, help='Attestation Type selection')
    parser_attest.add_argument('-c', '--config', type=str, required=True, help='ITA environment argument')
    parser_attest.add_argument('-u', '--user-data', help='User Data in base64 encoded format')
    parser_attest.add_argument('-p', '--policy-ids', help='Trust Authority Policy Ids, comma separated')
    parser_attest.add_argument('-r', '--request-id', help='Trust Authority Request Id')
    parser_attest.set_defaults(func=cmd_attest)

    # verify command
    parser_verify = subparsers.add_parser("verify", help="Verify command")
    parser_verify.add_argument('-c', '--config', type=str, required=True, help='ITA environment argument')
    parser_verify.add_argument('-t', '--token', type=str, required=True, help='Token in JWT format')
    parser_verify.set_defaults(func=cmd_verify)

    if len(sys.argv)==1:
        parser.print_help(sys.stderr)
        sys.exit(1)
    else:
        args = parser.parse_args()
        args.func(args)
    

if __name__ == '__main__':
    main()
