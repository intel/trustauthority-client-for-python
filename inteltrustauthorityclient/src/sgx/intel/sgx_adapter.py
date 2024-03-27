import json
import ctypes
import base64
import logging as log
from dataclasses import dataclass
from ctypes import *
from src.connector.evidence import Evidence
from src.resources import constants as const


@dataclass
class evidenceAdapterResponse:
    type: int
    Evidence: str
    user_data: str
    eventLog: str

# class sgx_config_svn_t(ctypes.Structure): #done
#     _fields_ = [("value", ctypes.c_short)]

# class sgx_misc_select_t(ctypes.Structure): #done
#     _fields_ = [("value", ctypes.c_int)]

# class sgx_config_id_t(ctypes.Structure): #done
#     _fields_ = [("id", ctypes.c_byte * 64)]

class sgx_attributes_t(ctypes.Structure): #done
    _fields_ = [("flags", ctypes.c_uint64), ("xfrm", ctypes.c_uint64)]

class sgx_measurement_t(ctypes.Structure): #done
    _fields_ = [("m", ctypes.c_uint8 * 32)]

class sgx_target_info_t(ctypes.Structure):
    _fields_ = [
        ("mr_enclave", sgx_measurement_t),
        ("attributes", sgx_attributes_t),
        ("reserved1", ctypes.c_uint8 * 2),
        ("config_svn", ctypes.c_uint16),
        ("misc_select", ctypes.c_uint32),
        ("reserved2", ctypes.c_uint8 * 8),
        ("config_id", c_uint8 * 64),
        ("reserved3", ctypes.c_uint8 * 384)
    ]

class sgx_cpu_svn_t(ctypes.Structure): #done
    _fields_ = [("svn", ctypes.c_uint8 * 16)]


class sgx_report_data_t(ctypes.Structure): #done
    _fields_ = [("d", c_uint8 * 64)]

class sgx_isvext_prod_id_t(ctypes.Structure): #done
    _fields_ = [("id", ctypes.c_uint8 * 16)]

class sgx_report_body_t(ctypes.Structure):
    _fields_ = [
        ("cpu_svn", sgx_cpu_svn_t),
        ("misc_select", ctypes.c_uint32),
        ("reserved1", ctypes.c_uint8 * 12),
        ("isv_ext_prod_id", ctypes.c_uint8 * 16),
        ("attributes", sgx_attributes_t),
        ("mr_enclave", sgx_measurement_t),
        ("reserved2", ctypes.c_uint8 * 32),
        ("mr_signer", sgx_measurement_t),
        ("reserved3", ctypes.c_uint8 * 32),
        ("config_id", ctypes.c_uint8 * 64),
        ("isv_prod_id", ctypes.c_uint16),
        ("isv_svn", ctypes.c_uint16),
        ("config_svn", ctypes.c_uint16),
        ("reserved4", ctypes.c_uint8 * 42),
        ("isv_family_id", ctypes.c_uint8 * 16),
        ("report_data", sgx_report_data_t)
    ]

class sgx_key_id_t(ctypes.Structure): #done 
    _fields_ = [("id", ctypes.c_uint8 * 32)]

class sgx_mac_t(ctypes.Structure):
    _fields_ = [("mac", ctypes.c_uint8 * 16)]

class sgx_report_t(ctypes.Structure):
    _fields_ = [
        ("body", sgx_report_body_t),
        ("key_id", sgx_key_id_t),
        ("mac", sgx_mac_t)
    ]


class SGXAdapter:
    def __init__(self, eid, user_data, report_function):
        self.eid = eid
        self.user_data = user_data
        self.report_function = report_function

    def collect_evidence(self, nonce=None) -> evidenceAdapterResponse:
        try:
            # Load the SGX DCAP library
            sgx_dcap_ql = ctypes.CDLL("libsgx_dcap_ql.so")
        except FileNotFoundError as e:
            log.exception(
                f"Caught Exception in loading the libsgx_dcap_ql.so library: {e}"
            )
            return None
        except OSError as e:
            log.exception(
                f"Caught Exception in loading the libsgx_dcap_ql.so library: {e}"
            )
            return None
        except Exception as e:
            log.exception(
                f"Caught Exception in loading the libsgx_dcap_ql.so library: {e}"
            )
            return None
        

        sgx_dcap_ql.sgx_qe_get_target_info.argtypes = [ctypes.POINTER(sgx_target_info_t)]
        sgx_dcap_ql.sgx_qe_get_target_info.restype = ctypes.c_int

        sgx_dcap_ql.sgx_qe_get_quote_size.argtypes = [ctypes.POINTER(ctypes.c_int)]
        sgx_dcap_ql.sgx_qe_get_quote_size.restype = ctypes.c_int

        sgx_dcap_ql.sgx_qe_get_quote.argtypes = [ctypes.POINTER(sgx_report_t), ctypes.c_int, ctypes.c_void_p]
        sgx_dcap_ql.sgx_qe_get_quote.restype = ctypes.c_int

        ret_val = ctypes.c_int(0)

        # Define structs required to be passed to fetch the report
        qe3_target = sgx_target_info_t()
        p_report = sgx_report_t()

        # Fetch target info by calling the respective sgx sdk function
        qe3_ret = sgx_dcap_ql.sgx_qe_get_target_info(ctypes.byref(qe3_target))
        if qe3_ret != 0:
            raise RuntimeError(f"sgx_qe_get_target_info return error code {hex(qe3_ret)}")

        # Create Nonce object based on nonce input provided by user
        nonce_ptr = ctypes.create_string_buffer(nonce)

        # Call the report function
        status = self.report_function(self.eid, ctypes.byref(ret_val), ctypes.byref(qe3_target), nonce_ptr, len(nonce), ctypes.byref(p_report))
        if status != 0:
            raise RuntimeError(f"Report callback returned error code {hex(status)}")
        if ret_val.value != 0:
            raise RuntimeError(f"Report retval returned {hex(ret_val.value)}")

        # Quote size C native object
        quote_size = ctypes.c_int()

        # Fetch the quote size by calling the respective sgx sdk function
        qe3_ret = sgx_dcap_ql.sgx_qe_get_quote_size(ctypes.byref(quote_size))
        if qe3_ret != 0:
            raise RuntimeError(f"sgx_qe_get_quote_size return error code {hex(qe3_ret)}")

        # Create a quote buffer object with the required quote size
        quote_buffer = ctypes.create_string_buffer(quote_size.value)

        # Fetch the sgx quote by calling the respective sgx sdk function
        qe3_ret = sgx_dcap_ql.sgx_qe_get_quote(ctypes.byref(p_report), quote_size.value, quote_buffer)
        if qe3_ret != 0:
            raise RuntimeError(f"sgx_qe_get_quote return error code {hex(qe3_ret)}")

        # Convert C native quote buffer to bytes
        # result = bytes(quote_buffer[:quote_size.value])
        quote_data = base64.b64encode(bytearray(quote_buffer[:quote_size.value])).decode("utf-8")
        user_data_encoded = base64.b64encode(self.user_data).decode("utf-8")
        return Evidence(0,quote_data,None, user_data_encoded, None, const.INTEL_SGX_ADAPTER)