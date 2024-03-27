"""
Copyright (c) 2023-2024 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""
import ctypes
import json
import sys
import os
from src.connector import config, connector
from src.resources import logger as logger
from src.resources import constants as const
from src.sgx.intel.sgx_adapter import SGXAdapter

import logging as log

def create_sgx_enclave(enclave_path):
    # try:
    c_lib = ctypes.CDLL("libsgx_urts.so")

    class sgx_enclave_id_t(ctypes.Structure):
        _fields_ = [("handle", ctypes.c_void_p)]

    class sgx_launch_token_t(ctypes.c_uint8 * 1024):
        pass

    c_lib.sgx_create_enclave.argtypes = [
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.POINTER(sgx_launch_token_t),
        ctypes.POINTER(ctypes.c_int),
        ctypes.POINTER(sgx_enclave_id_t),
        ctypes.c_void_p
    ]
    c_lib.restype = ctypes.c_int
    launch_token = sgx_launch_token_t()
    enclave_id = sgx_enclave_id_t()
    token_updated = ctypes.c_int(0)
    print("@@@@@@@@@@@@@@@@@")
    status = c_lib.sgx_create_enclave(
        enclave_path.encode(),
        0,
        ctypes.byref(launch_token),
        ctypes.byref(token_updated),
        ctypes.byref(enclave_id),
        None
    )
    if status != 0:
        print(f"Error creating enclave. SGX error code: {hex(status)}")
        # sgx_lib.sgx_destroy_enclave(enclave_id.handle)
        exit(1)

    return enclave_id, None


# except:
#   print("OS %s not recognized" % (sys.platform))
#   return None, None


def loadPublicKey(eid):
    c_lib = ctypes.CDLL("./minimal-enclave/libutils.so")

    #class sgx_enclave_id_t(ctypes.Structure):
    #    _fields_ = [("handle", ctypes.c_ulonglong)]

    #class sgx_enclave_id_t(ctypes.Structure):
    #    _fields_ = [("handle", ctypes.c_void_p)]

    c_lib.argtypes = [
        ctypes.c_long,
        ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8)),
        ctypes.POINTER(ctypes.c_uint32),
    ]
    c_lib.restype = ctypes.c_int
    key_buf = ctypes.POINTER(ctypes.c_uint8)()
    key_size = ctypes.c_uint32()
    status = c_lib.get_public_key(eid, ctypes.byref(key_buf), ctypes.byref(key_size))
    if status != 0:
        print(f"Error creating public key. SGX error code: {hex(status)}")
        exit(1)
    byte_array = bytes(key_buf)
    public_key = ctypes.cast(key_buf, ctypes.POINTER(ctypes.c_uint8 * key_size.value)).contents
    print(public_key)
    return bytearray(public_key), None

def main():
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

    # enclave related all work
    enclave_path = "./minimal-enclave/enclave.signed.so"
    eid, err = create_sgx_enclave(enclave_path)
    print("@@@@@@@@@@@@   Enclave id  : ", eid)
    pub_bytes, err = loadPublicKey(eid)
    print("#################3   public key : ", pub_bytes)
    try:
        # Populate config object
        config_obj = config.Config(
            config.RetryConfig(
                int(retry_wait_time_min), int(retry_wait_time_max), int(retry_max)
            ),
            trustauthority_base_url,
            trustAuthority_api_url,
            trust_authority_api_key,
        )
    except ValueError as exc:
        log.error(
            "Either retry_wait_time_min or retry_wait_time_max or retry_max is not a valud integer"
        )
        exit(1)

    ita_connector = connector.ITAConnector(config_obj)
    user_data = "data generated inside tee"
    adapter_type = os.getenv("ADAPTER_TYPE")
    print(adapter_type)
    if adapter_type is None:
        log.error("ADAPTER_TYPE is not set.")
        exit(1)
    adapter = None
    if(adapter_type == const.INTEL_SGX_ADAPTER):
        c_lib = ctypes.CDLL("./minimal-enclave/libutils.so")
        adapter = SGXAdapter(eid, pub_bytes, ctypes.pointer(c_lib.enclave_create_report))
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

# main for function call.
if __name__ == "__main__":
    main()
    #enclave_path = "./minimal-enclave/enclave.signed.so"
    #eid, err = create_sgx_enclave(enclave_path)