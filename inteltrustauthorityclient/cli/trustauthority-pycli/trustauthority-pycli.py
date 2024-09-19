"""
Copyright (c) 2024 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""
# trustauthority-pycli

import argparse
import json
import uuid
import sys
import os
import base64
from inteltrustauthorityclient.resources import constants as const
from inteltrustauthorityclient.connector import config, connector
from inteltrustauthorityclient.tdx.tdx_adapter import TDXAdapter
from inteltrustauthorityclient.nvgpu.gpu_adapter import GPUAdapter

def cmd_evidence(args):
    if args.nonce != None:
        try:
            nonce_bytes = base64.b64decode(args.nonce, validate=True)
        except Exception as err:
            print(f"Error while base64 decoding of nonce: : {err}")
            exit(1)
    else:
        nonce_bytes = None 

    # Collect Intel TDX evidence(quote)
    if args.attest_type == 'tdx':
        if args.user_data != None:
            try:
                user_data_bytes = base64.b64decode(args.user_data, validate=True)
            except Exception as err:
                print(f"Error while base64 decoding of user data: : {err}")
                exit(1)
        else:
            user_data_bytes = b"" 

        tdx_adapter = TDXAdapter(user_data_bytes)
        evidence = tdx_adapter.collect_evidence(nonce_bytes)
        if evidence is None:
            print("TDX Quote is not returned")
            return None
        print(f"TDX Quote : {evidence.evidence}")

    # Collect NVGPU evidence
    elif args.attest_type == 'nvgpu':
        if args.user_data != None:
            print("User Data (-u) is used in 'tdx' or 'tdx+nvgpu' attestaion")
            exit(1)
        gpu_adapter = GPUAdapter()
        evidence = gpu_adapter.collect_evidence(nonce_bytes)
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

    # Check if the token signing algorithm is supported
    if args.token_sign_alg != None:
        tsa = args.token_sign_alg
        if tsa not in ["RS256", "PS384"]:
            print(f"Unsupported token signing algorithm {tsa}, refer help section for supported algorithms")
            exit(1)
       
    if args.user_data != None:
        if args.attest_type =='nvgpu':
            print("User Data (-u) is used in 'tdx' or 'tdx+nvgpu' attestaion")
            exit(1)
        try:
            user_data_bytes = base64.b64decode(args.user_data)
        except Exception as err:
            print(f"Error while base64 decoding of user data: : {err}")
            exit(1)
    else:
        user_data_bytes = b""

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

    try:
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
    except ValueError as exc:
        log.error(f"Value Error in config object creation : {exc}")
        exit(1)

    if config_obj == None:
        log.error("Error in config() instance initialization")
        exit(1)

    ita_connector = connector.ITAConnector(config_obj)

    if args.attest_type == 'tdx':
        tdx_adapter = TDXAdapter(user_data_bytes)
        tdx_attest_args = connector.AttestArgs(tdx_adapter, args.token_sign_alg, args.policy_must_match, args.request_id, policyIds)
        gpu_attest_args = None
    elif args.attest_type =='nvgpu':
        gpu_adapter = GPUAdapter()
        gpu_attest_args = connector.AttestArgs(gpu_adapter, args.token_sign_alg, args.policy_must_match, args.request_id, policyIds)
        tdx_attest_args = None
    elif args.attest_type =='tdx+nvgpu':
        tdx_adapter = TDXAdapter(user_data_bytes)
        gpu_adapter = GPUAdapter()
        tdx_attest_args = connector.AttestArgs(tdx_adapter, args.token_sign_alg, args.policy_must_match, args.request_id, policyIds)
        gpu_attest_args = connector.AttestArgs(gpu_adapter, args.token_sign_alg, args.policy_must_match, args.request_id, policyIds)
    else:
        print("Attestation Type %s is unknown.", args.attest_type)
        exit(1)

    response = ita_connector.attest_v2(tdx_attest_args, gpu_attest_args)

    if response is None:
        print("Attestation Token is not returned.")
        return None 

    if response.headers:
        response_headers_json = json.loads(response.headers.replace("'", '"'))
        trace_id = response_headers_json.get("trace-id")
        print(f"Trace Id: {trace_id}")
        request_id = response_headers_json.get("request-id")
        if request_id != None:
            print(f"Request Id: {request_id}")

    token = response.token
    print(f"Attestation token : {token}")


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

    try:
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
    except ValueError as exc:
        log.error(f"Value Error in config object creation : {exc}")
        exit(1)

    if config_obj == None:
        log.error("Error in config() instance initialization")
        exit(1)

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
    parser = argparse.ArgumentParser(description="Trust Authority Python CLI")
    subparsers = parser.add_subparsers(title="Commands", dest="command", help="Command to execute")

    # evidence command
    parser_evidence = subparsers.add_parser("evidence", help="Evidence command")
    parser_evidence.add_argument('-a', '--attest-type', choices=['tdx', 'nvgpu'], required=True, help='Attestation Type selection')
    parser_evidence.add_argument('-n', '--nonce', help="Nonce in base64 encoded format")
    parser_evidence.add_argument('-u', '--user-data', help="User Data in base64 encoded format (*Use for 'tdx' or 'tdx+nvgpu' attestation)")
    parser_evidence.set_defaults(func=cmd_evidence)

    # attest command
    parser_attest = subparsers.add_parser("attest", help="Attest command")
    parser_attest.add_argument('-a', '--attest-type', choices=['tdx','nvgpu','tdx+nvgpu'], required=True, help="Attestation Type selection")
    parser_attest.add_argument('-c', '--config', type=str, required=True, help="Trust Authority config in JSON format")
    parser_attest.add_argument('-u', '--user-data', help="User Data in base64 encoded format (*Use for 'tdx' or 'tdx+nvgpu' attestation)")
    parser_attest.add_argument('-p', '--policy-ids', help="Trust Authority Policy Ids, comma separated without space")
    parser_attest.add_argument('-r', '--request-id', help="Request id to be associated with request")
    parser_attest.add_argument('-s', '--token-sign-alg', choices=["RS256","PS384"], help="Token Signing Algorithm to be used, support PS384 and RS256")
    parser_attest.add_argument('--policy-must-match', default=False, action="store_true", help="Enforce policies match during attestation")
    parser_attest.set_defaults(func=cmd_attest)

    # verify command
    parser_verify = subparsers.add_parser("verify", help="Verify command")
    parser_verify.add_argument('-c', '--config', type=str, required=True, help="ITA environment argument")
    parser_verify.add_argument('-t', '--token', type=str, required=True, help="Token in JWT format")
    parser_verify.set_defaults(func=cmd_verify)

    if len(sys.argv)==1:
        parser.print_help(sys.stderr)
        sys.exit(1)
    else:
        args = parser.parse_args()
        args.func(args)
    

if __name__ == '__main__':
    main()
