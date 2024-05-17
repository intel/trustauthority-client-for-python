# trustauthority-cli-python v1.0

import argparse
import json
import sys
import os
import base64
import logging as log
from urllib.parse import urlparse
from dotenv import load_dotenv
from inteltrustauthorityclient.resources import constants as const
from inteltrustauthorityclient.connector import config, connector
from inteltrustauthorityclient.tdx.intel.tdx_adapter import TDXAdapter
from inteltrustauthorityclient.nvgpu.gpu_adapter import GPUAdapter

log.disable(log.NOTSET)

def cmd_evidence(args):

    if args.attest_type == 'tdx':
        if args.user_data:
           #    user_data_bytes = base64.b64decode(args.user_data)
            user_data_bytes = args.user_data
        else:
            #user_data = "data generated inside tee"
            user_data_bytes = ""

        if args.nonce:
            nonce_bytes = base64.b64decode(args.nonce)
        else:
            nonce_bytes = None

        tdx_adapter = TDXAdapter(user_data_bytes, None)
        #tdx_adapter = TDXAdapter(args.user_data)
        evidence = tdx_adapter.collect_evidence(nonce_bytes)
        if evidence == None:
           log.error("Failed to get the evidence") 
        print(evidence.quote)
        #log.info("Quote : %s", base64.b64encode(evidence.quote).decode())

    elif args.attest_type == 'nvgpu':
        gpu_adapter = GPUAdapter()

        evidence = gpu_adapter.collect_evidence(args.nonce)
        print(evidence.evidence)

def cmd_attest(args):

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

    trust_authority_request_id = cf_dict['trust_authority_request_id']
    if trust_authority_request_id is None:
        log.error("TRUST_AUTHORITY_REQUEST_ID is not set.")
        exit(1)

    trust_authority_policy_id = cf_dict['trust_authority_policy_id']
    if trust_authority_policy_id is None:
        log.error("TRUST_AUTHORITY_POLICY_ID is not set.")
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
            #user_data_bytes = base64.b64decode(args.user_data)
            user_data_bytes = args.user_data
        else:
            #user_data = "data generated inside tee"
            user_data_bytes = "" 
        tdx_adapter = TDXAdapter(user_data_bytes, None)
        tdx_attest_args = connector.TDXAttestArgs(tdx_adapter, trust_authority_request_id)
        #attestation_token = ita_connector.attest_tdx(attest_args)
        attestation_token = ita_connector.attest_composite(tdx_attest_args, None)
        if attestation_token is None:
            log.error("Attestation Token is not returned.")
            exit(1)

        token = attestation_token.token
        #print(token)
        log.info(f"Attestation token : {token}")
        token_headers_json = json.loads(attestation_token.headers.replace("'", '"'))
        log.info(
            "Request id and Trace id are: %s, %s",
            token_headers_json.get("request-id"),
            token_headers_json.get("trace-id"),
        )

    elif args.attest_type =='nvgpu':
        gpu_adapter = GPUAdapter()
        gpu_attest_args = connector.GPUAttestArgs(gpu_adapter, trust_authority_request_id)
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
            #user_data_bytes = base64.b64decode(args.user_data)
            user_data_bytes = args.user_data
        else:
            #user_data = "data generated inside tee"
            user_data_bytes = ""

        if args.policy_ids != None:
            # policy_ids: An array of one to ten attestation policy IDs.
            if len(args.policy_ids) > constants.POLICY_IDS_MAX_LEN:
                log.error("policy count in request must be between 1 - 10")
                return None

            policy_ids = args.policy_ids
        else:
            policy_ids = None

        # Create TDX Adapter
        tdx_adapter = TDXAdapter(user_data_bytes, None)
        # Create GPU Adapter
        gpu_adapter = GPUAdapter()

        tdx_attest_args = connector.TDXAttestArgs(tdx_adapter, trust_authority_request_id, policy_ids)
        gpu_attest_args = connector.GPUAttestArgs(gpu_adapter, trust_authority_request_id, None)
        # Fetch Attestation Token from ITA
        attestation_token = ita_connector.attest_composite(tdx_attest_args, gpu_attest_args)
        if attestation_token is None:
            log.error("Attestation Token is not returned.")
            exit(1)
        token = attestation_token.token
        #log.info(f"Attestation token : {token}")
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
            print("Token Verification Successful")
            print(f"Verified Attestation Token : {verified_token}")
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
