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
                exit(1)
        else:
            user_data_bytes = b"" 

        if args.nonce:
            # Input Validation: limit the nonce input size to 64 bytes
            if len(args.nonce) > 64:
                print("Nonce should be less than 64 bytes in length")
                exit(1)
            try:
                nonce_bytes = base64.b64decode(args.nonce)
            except Exception as err:
                print(f"Error while base64 decoding of nonce: : {err}")
                exit(1)
        else:
            nonce_bytes = b"" 

        # eventLogger is not used for Python CLI
        tdx_adapter = TDXAdapter(user_data_bytes, None)
        evidence = tdx_adapter.collect_evidence(nonce_bytes)
        if evidence is None:
            print("TDX Quote is not returned")
            return None
        print(f"TDX Quote : {evidence.quote}")

    elif args.attest_type == 'nvgpu':
        gpu_adapter = GPUAdapter()

        if args.nonce:
            # Input Validation: limit the nonce input size to 64 bytes
            if len(args.nonce) > 64:
                print("Nonce should be less than 64 bytes in length")
                exit(1)
            try:
                # Transform to NVGPU nonce (should be 32 bytes/Hex string)
                nonce_bytes = base64.b64decode(args.nonce)
                gpu_nonce = hashlib.sha256(nonce_bytes).hexdigest()
            except Exception as err:
                print(f"Error while base64 decoding of nonce: : {err}")
                exit(1)
        # if nonce is not provided by a user, GPU Adapter will generate random nonce 
        else:
            gpu_nonce = None

        evidence = gpu_adapter.collect_evidence(gpu_nonce)
        if evidence is None:
            print("GPU Evidence is not returned")
            return None
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

    # Check if policy uuid is valid and the number of policy counts not exceeded.
    if args.policy_ids != None:
        policyIds = args.policy_ids.split(",")
        if len(policyIds) > const.POLICY_IDS_MAX_LEN:
            print("policy count in request must be between 1 - 10")
            exit(1)
        for pId in policyIds:
            if not config.validate_uuid(pId):
                print(f"Invalid policy UUID :{pId}")
                exit(1)
    else:
        policyIds = None 

    # Check if the token signing altorithm is supported
    if args.sign_alg != None:
        tsa = args.sign_alg
        if tsa not in ["RS256", "PS384"]:
            print(f"Token Signing Algorithm {tsa} is unsupported, supported algorithms are PS384 and RS256")
            exit(1)
       
    # Not enforcing policy match during attestation (CLI does not provide policy_must_match as an argument option: set to default/False)
    policy_must_match = False

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
                exit(1)
        else:
            user_data_bytes = b""

        tdx_adapter = TDXAdapter(user_data_bytes, None)
        tdx_attest_args = connector.AttestArgs(tdx_adapter, args.sign_alg, policy_must_match, args.request_id, policyIds)
        attestation_token = ita_connector.attest_v2(tdx_attest_args, None)
        if attestation_token is None:
            print("Attestation Token is not returned.")
            return None 

        token = attestation_token.token
        print(f"Attestation token : {token}")

    elif args.attest_type =='nvgpu':
        gpu_adapter = GPUAdapter()
        gpu_attest_args = connector.AttestArgs(gpu_adapter, args.sign_alg, policy_must_match, args.request_id, policyIds)
        attestation_token = ita_connector.attest_v2(None, gpu_attest_args)
        if attestation_token is None:
            print("Attestation Token is not returned.")
            return None 

        token = attestation_token.token
        print(f"Attestation token : {token}")

    elif args.attest_type =='tdx+nvgpu':
        if args.user_data:
            try:
                user_data_bytes = base64.b64decode(args.user_data)
            except Exception as err:
                print(f"Error while base64 decoding of user data: : {err}")
                exit(1)
        else:
            user_data_bytes = b"" 

        # Create TDX Adapter
        tdx_adapter = TDXAdapter(user_data_bytes, None)
        # Create GPU Adapter
        gpu_adapter = GPUAdapter()

        tdx_attest_args = connector.AttestArgs(tdx_adapter, args.sign_alg, policy_must_match, args.request_id, policyIds)
        gpu_attest_args = connector.AttestArgs(gpu_adapter, args.sign_alg, policy_must_match, args.request_id, policyIds)
        attestation_token = ita_connector.attest_v2(tdx_attest_args, gpu_attest_args)
        if attestation_token is None:
            print("Attestation Token is not returned.")
            return None 
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
    parser_attest.add_argument('-p', '--policy-ids', help='Trust Authority Policy Ids, comma separated without space')
    parser_attest.add_argument('-r', '--request-id', help='Trust Authority Request Id')
<<<<<<< HEAD
    parser_attest.add_argument('-s', '--sign-alg', choices=["RS256", "PS384"], help='Trust Authority Token Signing Algorithm')
=======
    parser_attest.add_argument('-s', '--sign-alg', help='Trust Authority Token Signing Algorithm')
>>>>>>> 54968e7 (Removed unittest for NVGPU (due to NV SDK issue in CI))
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
