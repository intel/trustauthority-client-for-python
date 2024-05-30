# trustauthority-cli-python v1.0

import argparse
import json
import uuid
import sys
import os
import base64
import logging as log
from urllib.parse import urlparse
from dotenv import load_dotenv
from inteltrustauthorityclient.resources import constants as constants
from inteltrustauthorityclient.connector import config, connector
from inteltrustauthorityclient.tdx.intel.tdx_adapter import TDXAdapter
from inteltrustauthorityclient.nvgpu.gpu_adapter import GPUAdapter

def cmd_evidence(args):
    if args.attest_type == 'tdx':
        if args.user_data:
            user_data_bytes = args.user_data

        if args.nonce:
            nonce_bytes = base64.b64decode(args.nonce)

        # eventLogger is not used for Python CLI
        tdx_adapter = TDXAdapter(user_data_bytes, None)
        evidence = tdx_adapter.collect_evidence(nonce_bytes)
        if evidence == None:
           log.error("Failed to get the evidence") 
        log.info(f"TDX quote : {evidence.quote}")

    elif args.attest_type == 'nvgpu':
        gpu_adapter = GPUAdapter()

        evidence = gpu_adapter.collect_evidence(args.nonce)
        log.info(f"GPU evidence : {evidence.evidence}")

def cmd_attest(args):
    # Check if request id is valid
    if args.request_id != None:
       if len(args.request_id) > constants.REQUEST_ID_MAX_LEN:
           log.error("Request ID should be atmost 128 characters long.") 
           exit(1)
       for req_char in args.request_id:
           if req_char != '-' and req_char.isalnum() == False:
               log.error("Request ID should contain only a-z, A-Z, 0-9, and - (hyphen), Special characters are not allowed.")
               exit(1)

       trust_authority_request_id = args.request_id

    # Check if policy uuid is valid and the number of policy counts not exceeded.
    policyIds = []
    if args.policy_ids != None:
       pIds = args.policy_ids.split(",")
       if len(pIds) > constants.POLICY_IDS_MAX_LEN:
           log.error("policy count in request must be between 1 - 10")
           exit(1)
       for pId in pIds:
           try:
               uid = uuid.UUID(pId)
           except ValueError:
               log.error(f"Invalid policy UUID :{pId}")
               exit(1)
           else:
               policyIds.append(uid)

    # Read ITA Env configuration from json file
    with open(args.config, 'r') as cf:
        cf_dict = json.load(cf)

    trustauthority_base_url = cf_dict['trustauthority_base_url']
    if trustauthority_base_url is None:
        log.error("TRUSTAUTHORITY_BASE_URL is not set.")
        exit(1)

    trustauthority_api_url = cf_dict['trustauthority_api_url']
    if trustauthority_api_url is None:
        log.error("TRUSTAUTHORITY_API_URL is not set.")
        exit(1)

    trustauthority_api_key = cf_dict['trustauthority_api_key']
    if trustauthority_api_key is None:
        log.error("TRUSTAUTHORITY_API_KEY is not set.")
        exit(1)

    cf.close()

    config_obj = config.Config(
            config.RetryConfig(
                1, 1, 1
            ),
            trustauthority_base_url,
            trustauthority_api_url,
            trustauthority_api_key,
        )

    if config_obj == None:
        log.error("Error in config() instance initialization")
        exit(1)

    ita_connector = connector.ITAConnector(config_obj)

    if args.attest_type == 'tdx':
        if args.user_data:
            user_data_bytes = args.user_data
        else:
            user_data_bytes = "" 
        tdx_adapter = TDXAdapter(user_data_bytes, None)
        tdx_attest_args = connector.AttestArgs(tdx_adapter, trust_authority_request_id, policyIds)
        attestation_token = ita_connector.attest_composite(tdx_attest_args, None)
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

    elif args.attest_type =='nvgpu':
        gpu_adapter = GPUAdapter()
        gpu_attest_args = connector.AttestArgs(gpu_adapter, trust_authority_request_id)
        attestation_token = ita_connector.attest_composite(None, gpu_attest_args)
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

    elif args.attest_type =='tdx+nvgpu':
        if args.user_data:
            user_data_bytes = args.user_data

        # Create TDX Adapter
        tdx_adapter = TDXAdapter(user_data_bytes, None)
        # Create GPU Adapter
        gpu_adapter = GPUAdapter()

        tdx_attest_args = connector.AttestArgs(tdx_adapter, trust_authority_request_id, policyIds)
        # GPU appraisal policy is not supported yet until v2 policy is available. 
        gpu_attest_args = connector.AttestArgs(gpu_adapter, trust_authority_request_id, None)
        # Fetch Attestation Token from ITA
        attestation_token = ita_connector.attest_composite(tdx_attest_args, gpu_attest_args)
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

    else:
        log.error("Unknown Attestation Type %s is unknown.", args.attest_type)
        exit(1)


def cmd_verify(args):

    with open(args.config, 'r') as cf:
        cf_dict = json.load(cf)

    trustauthority_base_url = cf_dict['trustauthority_base_url']
    if trustauthority_base_url is None:
        log.error("TRUSTAUTHORITY_BASE_URL is not set.")
        exit(1)

    trustauthority_api_url = cf_dict['trustauthority_api_url']
    if trustauthority_api_url is None:
        log.error("TRUSTAUTHORITY_API_URL is not set.")
        exit(1)

    trustauthority_api_key = cf_dict['trustauthority_api_key']
    if trustauthority_api_key is None:
        log.error("TRUSTAUTHORITY_API_KEY is not set.")
        exit(1)

    cf.close()

    config_obj = config.Config(
            config.RetryConfig(
                1, 1, 1
            ),
            trustauthority_base_url,
            trustauthority_api_url,
            trustauthority_api_key,
        )

    if config_obj == None:
        log.error("Error in config() instance initialization")
        exit(1)

    ita_connector = connector.ITAConnector(config_obj)

    if args.token == None:
        log.error("Token needs to be provided")
        exit(1)
    else:
        try:
            verified_token = ita_connector.verify_token(args.token)
        except Exception as exc:
            verified_token = None
            log.error(f"Token verification returned exception : {exc}")
        if verified_token != None:
            log.info("Token Verification Successful")
            log.info(f"Verified Attestation Token : {verified_token}")
        else:
            log.error("Token Verification failed")
            exit(1)

def main():
    parser = argparse.ArgumentParser(description='Trust Authority CLI for Python')
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
