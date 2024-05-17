# trustauthority-cli-python v1.0

import argparse
import ctypes
import json
import sys
import os
import base64
import jwt
import pprint
from urllib.parse import urlparse
import validators
import uuid
import logging as log
import configparser
from os.path import join, dirname
from urllib.parse import urlparse
from dotenv import load_dotenv
from src.resources import logging as logger
from src.resources import constants as const
from src.tdx.tdx_adapter import TDXAdapter
from src.nvgpu.gpu_adapter import GPUAdapter
from src.connector import config, connector

log.disable(log.NOTSET)

def cmd_evidence(args):
    #print("Executing quote command:", args)

    if args.attest_type == 'tdx':
        #user_data = "data generated inside tee"
        
        if args.user_data:
            user_data_bytes = base64.b64decode(args.user_data)
        else:
            user_data_bytes = None

        if args.nonce:
            nonce_bytes = base64.b64decode(args.nonce)
        else:
            nonce_bytes = None

        tdx_adapter = TDXAdapter(user_data_bytes, None)
        #tdx_adapter = TDXAdapter(args.user_data)
        evidence = tdx_adapter.collect_evidence(nonce_bytes)
        if evidence == None:
           log.error("Failed to get the evidence") 
        #log.info("Quote : %s", base64.b64encode(evidence.quote).decode())
        print(base64.b64encode(evidence.quote).decode())
        #evidence = tdx_adapter.collect_evidence(args.nonce)
        #print(evidence.Evidence, file=os.Stdout)

    elif args.attest_type == 'nvgpu':
        gpu_adapter = GPUAdapter()
        evidence = gpu_adapter.collect_evidence(args.nonce)
        print(evidence.evidence)

def cmd_token(args):
    #print("Executing token command:", args)

    #to-do
    with open(args.config, 'r') as cf:
        cf_dict = json.load(cf)
    #print(cf_dict['trustauthority_api_url'])

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

    #trust_authority_request_id = "1234"
    #trust_authority_policy_id = None
    #trust_authority_request_id = cf_dict['trust_authority_request_id']
    #if trust_authority_request_id is None:
    #    log.error("TRUST_AUTHORITY_REQUEST_ID is not set.")
    #    exit(1)

    trust_authority_policy_id = cf_dict['trust_authority_policy_id']
    if trust_authority_policy_id is None:
        log.error("TRUST_AUTHORITY_POLICY_ID is not set.")
        exit(1)

    cf.close()


    #trustauthority_base_url = "https://amber-dev02-user2.project-amber-smas.com" 
    #trustauthority_api_url = "https://api-dev02-user2.project-amber-smas.com" 
    #trustauthority_api_key = "djE6NmQ0NTA5OGMtMzY1Zi00NzI0LWFmZmYtNTZmOWVkM2I3Yzg1OnJidmJrU0RDOXA5aWNJREIzbDlmVklrRU50djNXV1c2c1oxRjhGdzk="

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
    
    #print(args.config.readlines())
    #data = json.load(args.config)
    #for key, value in data.items():
    #    print(key, value)

    if args.attest_type == 'tdx':
        #user_data = "data generated inside tee"
        user_data = args.user_data
        tdx_adapter = TDXAdapter(user_data)
        attest_args = connector.TDXAttestArgs(tdx_adapter, trust_authority_request_id)
        attestation_token = ita_connector.attest_tdx(attest_args)
        if attestation_token is None:
            log.error("Attestation Token is not returned.")
            exit(1)

        token = attestation_token.token
        print(token)
        log.info(f"Attestation token : {token}")
        token_headers_json = json.loads(attestation_token.headers.replace("'", '"'))
        log.info(
            "Request id and Trace id are: %s, %s",
            token_headers_json.get("request-id"),
            token_headers_json.get("trace-id"),
        )

    elif args.attest_type =='nvgpu':

        gpu_adapter = GPUAdapter()
        gpu_args = connector.GPUAttestArgs(gpu_adapter, trust_authority_request_id)
        # Fetch Attestation Token from ITA
        attestation_token = ita_connector.attest_gpu(gpu_args)
        if attestation_token is None:
            log.error("Attestation Token is not returned.")
            exit(1)
        token = attestation_token.token
        print(token)
        log.info(f"Attestation token : {token}")
        token_headers_json = json.loads(attestation_token.headers.replace("'", '"'))
        log.info(
            "Request id and Trace id are: %s, %s",
            token_headers_json.get("request-id"),
            token_headers_json.get("trace-id"),
        )

    elif args.attest_type =='tdx+nvgpu':
        # Create TDX Adapter
        user_data = "data generated inside tee"
        tdx_adapter = TDXAdapter(user_data)
        gpu_adapter = GPUAdapter()

        if trust_authority_policy_id != None:
            policy_ids = json.loads(trust_authority_policy_id)
            tdx_attest_args = connector.TDXAttestArgs(
                tdx_adapter, trust_authority_request_id, policy_ids
            )
            gpu_attest_args = connector.GPUAttestArgs(
                gpu_adapter, trust_authority_request_id, policy_ids=None
            )

        else:
            tdx_args = connector.TDXAttestArgs(tdx_adapter, trust_authority_request_id)
            gpu_args = connector.GPUAttestArgs(gpu_adapter, trust_authority_request_id)
        
        # Fetch Attestation Token from ITA
        attestation_token = ita_connector.attest_composite(tdx_args, gpu_args)
        if attestation_token is None:
            log.error("Attestation Token is not returned.")
            exit(1)
        token = attestation_token.token
        print(token)
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


def cmd_attest(args):
    print("Executing attest command:", args)

    with open(args.config, 'r') as cf:
        cf_dict = json.load(cf)
    #print(cf_dict['trustauthority_api_url'])

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

    #trust_authority_request_id = "1234"
    #trust_authority_policy_id = None
    trust_authority_request_id = cf_dict['trust_authority_request_id']
    if trust_authority_request_id is None:
        log.error("TRUST_AUTHORITY_REQUEST_ID is not set.")
        exit(1)

    trust_authority_policy_id = cf_dict['trust_authority_policy_id']
    if trust_authority_policy_id is None:
        log.error("TRUST_AUTHORITY_POLICY_ID is not set.")
        exit(1)

    cf.close()

    #trustauthority_base_url = "https://amber-dev02-user2.project-amber-smas.com"
    #trustauthority_api_url = "https://api-dev02-user2.project-amber-smas.com"
    #trustauthority_api_key = "djE6NmQ0NTA5OGMtMzY1Zi00NzI0LWFmZmYtNTZmOWVkM2I3Yzg1OnJidmJrU0RDOXA5aWNJREIzbDlmVklrRU50djNXV1c2c1oxRjhGdzk="

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

    #print(args.config.readlines())
    #data = json.load(args.config)
    #for key, value in data.items():
    #    print(key, value)

    if args.attest_type == 'tdx':
        #user_data = "data generated inside tee"
        user_data = args.user_data
        tdx_adapter = TDXAdapter(user_data)
        attest_args = connector.TDXAttestArgs(tdx_adapter, trust_authority_request_id)
        attestation_token = ita_connector.attest_tdx(attest_args)
        if attestation_token is None:
            log.error("Attestation Token is not returned.")
            exit(1)

        token = attestation_token.token
        print(token)
        log.info(f"Attestation token : {token}")
        token_headers_json = json.loads(attestation_token.headers.replace("'", '"'))
        log.info(
            "Request id and Trace id are: %s, %s",
            token_headers_json.get("request-id"),
            token_headers_json.get("trace-id"),
        )

    elif args.attest_type =='nvgpu':
        gpu_adapter = GPUAdapter()
        gpu_args = connector.GPUAttestArgs(gpu_adapter, trust_authority_request_id)
        # Fetch Attestation Token from ITA
        attestation_token = ita_connector.attest_gpu(gpu_args)
        if attestation_token is None:
            log.error("Attestation Token is not returned.")
            exit(1)
        token = attestation_token.token
        print(token)
        log.info(f"Attestation token : {token}")
        token_headers_json = json.loads(attestation_token.headers.replace("'", '"'))
        log.info(
            "Request id and Trace id are: %s, %s",
            token_headers_json.get("request-id"),
            token_headers_json.get("trace-id"),
        )

    elif args.attest_type =='tdx+nvgpu':
        # Create TDX Adapter
        user_data = "data generated inside tee"
        tdx_adapter = TDXAdapter(user_data)
        gpu_adapter = GPUAdapter()

        if trust_authority_policy_id != None:
            policy_ids = json.loads(trust_authority_policy_id)
            tdx_attest_args = connector.TDXAttestArgs(
                tdx_adapter, trust_authority_request_id, policy_ids
            )
            gpu_attest_args = connector.GPUAttestArgs(
                gpu_adapter, trust_authority_request_id, policy_ids=None
            )

        else:
            tdx_args = connector.TDXAttestArgs(tdx_adapter, trust_authority_request_id)
            gpu_args = connector.GPUAttestArgs(gpu_adapter, trust_authority_request_id)

        # Fetch Attestation Token from ITA
        attestation_token = ita_connector.attest_composite(tdx_args, gpu_args)
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

    else:
        log.error("Unknown Attestation Type %s is unknown.", args.attest_type)
        exit(1)


def cmd_verify(args):
    print("Executing verify command:", args)

    with open(args.config, 'r') as cf:
        cf_dict = json.load(cf)
    #print(cf_dict['trustauthority_api_url'])

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

    #trustauthority_base_url = "https://amber-dev02-user2.project-amber-smas.com"
    #trustauthority_api_url = "https://api-dev02-user2.project-amber-smas.com"
    #trustauthority_api_key = "djE6NmQ0NTA5OGMtMzY1Zi00NzI0LWFmZmYtNTZmOWVkM2I3Yzg1OnJidmJrU0RDOXA5aWNJREIzbDlmVklrRU50djNXV1c2c1oxRjhGdzk="

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
            log.info("Token Verification failed")

def main():

    #with open("config.json", "r") as cf:
    #    cfg_dict = json.load(cf)
    #print(cfg_dict["trustauthority_api_url"])

    parser = argparse.ArgumentParser(description='Trust Authority CLI App')
    subparsers = parser.add_subparsers(title="Commands", dest="command")

    # evidence
    parser_evidence = subparsers.add_parser("evidence", help="Evidence command")
    parser_evidence.add_argument('-a', '--attest-type', choices=['tdx', 'nvgpu'], required=True, help='Attestation Type selection')
    parser_evidence.add_argument('-n', '--nonce', help='Nonce in base64 encoded format')
    parser_evidence.add_argument('-u', '--user-data', help='User Data in base64 encoded format')
    parser_evidence.set_defaults(func=cmd_evidence)

    # token
    #parser_token = subparsers.add_parser("token", help="Token command")
    #parser_token.add_argument('-a', '--attest-type', choices=['tdx', 'nvgpu', 'tdx+nvgpu'], required=True, help='Attestation Type selection')
    #parser_token.add_argument('-c', '--config', type=argparse.FileType('r'), required=True, help='ITA environment argument')
    #parser_token.add_argument('-c', '--config', type=str, required=True, help='ITA environment argument')
    #parser_token.add_argument('-u', '--user-data', help='User Data in base64 encoded format')
    #parser_token.add_argument('-p', '--policy-ids', help='Trust Authority Policy Ids, comma separated')
    #parser_token.add_argument('-r', '--request_Ids', help='Request id to be associated with request')
    #parser_token.set_defaults(func=cmd_token)

    # attest
    parser_attest = subparsers.add_parser("attest", help="Attest command")
    parser_attest.add_argument('-a', '--attest-type', choices=['tdx', 'nvgpu', 'tdx+nvgpu'], required=True, help='Attestation Type selection')
    parser_attest.add_argument('-c', '--config', type=str, required=True, help='ITA environment argument')
    parser_attest.add_argument('-u', '--user-data', help='User Data in base64 encoded format')
    parser_attest.add_argument('-p', '--policy-ids', help='Trust Authority Policy Ids, comma separated')
    #parser_attest.add_argument('-r', '--request_Ids', help='Request id to be associated with request')
    parser_attest.set_defaults(func=cmd_attest)

    # verify
    parser_verify = subparsers.add_parser("verify", help="Verify command")
    parser_verify.add_argument('-t', '--token', required=True, help='Token in JWT format')
    parser_verify.set_defaults(func=cmd_verify)

    args = parser.parse_args()
    args.func(args)
    

if __name__ == '__main__':
    main()
