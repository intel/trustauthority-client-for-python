import ctypes
import base64
import logging as log
from dataclasses import dataclass
from ctypes import *
from inteltrustauthorityclient.connector.evidence import Evidence
from inteltrustauthorityclient.resources import constants as const


class sgx_attributes_t(ctypes.Structure):
    _fields_ = [("flags", ctypes.c_long), ("xfrm", ctypes.c_long)]


class sgx_measurement_t(ctypes.Structure):
    _fields_ = [("m", ctypes.c_uint8 * 32)]


sgx_config_svn_t = ctypes.c_uint16
sgx_misc_select_t = ctypes.c_uint32
sgx_config_id_t = ctypes.c_uint8 * 64


class sgx_target_info_t(ctypes.Structure):
    _fields_ = [
        ("mr_enclave", sgx_measurement_t),
        ("attributes", sgx_attributes_t),
        ("reserved1", ctypes.c_uint8 * const.SGX_TARGET_INFO_RESERVED1_BYTES),
        ("config_svn", sgx_config_svn_t),
        ("misc_select", sgx_misc_select_t),
        ("reserved2", ctypes.c_uint8 * const.SGX_TARGET_INFO_RESERVED2_BYTES),
        ("config_id", sgx_config_id_t),
        ("reserved3", ctypes.c_uint8 * const.SGX_TARGET_INFO_RESERVED3_BYTES),
    ]


class sgx_cpu_svn_t(ctypes.Structure):
    _fields_ = [("svn", ctypes.c_uint8 * 16)]


class sgx_report_data_t(ctypes.Structure):
    _fields_ = [("d", c_uint8 * 64)]


class sgx_isvext_prod_id_t(ctypes.Structure):
    _fields_ = [("id", ctypes.c_uint8 * 16)]


class sgx_report_body_t(ctypes.Structure):
    _fields_ = [
        ("cpu_svn", sgx_cpu_svn_t),
        ("misc_select", ctypes.c_uint32),
        ("reserved1", ctypes.c_uint8 * const.SGX_REPORT_BODY_RESERVED1_BYTES),
        ("isv_ext_prod_id", ctypes.c_uint8 * 16),
        ("attributes", sgx_attributes_t),
        ("mr_enclave", sgx_measurement_t),
        ("reserved2", ctypes.c_uint8 * const.SGX_REPORT_BODY_RESERVED2_BYTES),
        ("mr_signer", sgx_measurement_t),
        ("reserved3", ctypes.c_uint8 * const.SGX_REPORT_BODY_RESERVED3_BYTES),
        ("config_id", ctypes.c_uint8 * 64),
        ("isv_prod_id", ctypes.c_uint16),
        ("isv_svn", ctypes.c_uint16),
        ("config_svn", ctypes.c_uint16),
        ("reserved4", ctypes.c_uint8 * const.SGX_REPORT_BODY_RESERVED4_BYTES),
        ("isv_family_id", ctypes.c_uint8 * 16),
        ("report_data", sgx_report_data_t),
    ]


class sgx_key_id_t(ctypes.Structure):
    _fields_ = [("id", ctypes.c_uint8 * 32)]


class sgx_mac_t(ctypes.Structure):
    _fields_ = [("mac", ctypes.c_uint8 * 16)]


class sgx_report_t(ctypes.Structure):
    _fields_ = [
        ("body", sgx_report_body_t),
        ("key_id", sgx_key_id_t),
        ("mac", sgx_mac_t),
    ]


class SGXAdapter:
    """This class creates adapter which collects SGX Quote from Intel SGX platform."""

    def __init__(self, eid, report_function, user_data:bytearray=None) -> None:
        """Initializes Intel sgx adapter object
        Args:
            eid (string): Enclave id
            report_function (function): Function to Get Enclave Report Data
            user_data (byte array, optional): User data.
        """
        self.eid = eid
        self.report_function = report_function
        self.user_data = user_data

    def collect_evidence(self, nonce=None) -> Evidence:
        """This Function calls Intel SGX Dcap Library Functions to get SGX quote.

        Args:
            nonce ([]byte]): optional nonce provided by Intel Trust Authority

        Returns:
            evidence: object to Evidence class
        """
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

        sgx_dcap_ql.sgx_qe_get_target_info.argtypes = [
            ctypes.POINTER(sgx_target_info_t)
        ]
        sgx_dcap_ql.sgx_qe_get_target_info.restype = ctypes.c_int

        sgx_dcap_ql.sgx_qe_get_quote_size.argtypes = [ctypes.POINTER(ctypes.c_int)]
        sgx_dcap_ql.sgx_qe_get_quote_size.restype = ctypes.c_int

        sgx_dcap_ql.sgx_qe_get_quote.argtypes = [
            ctypes.POINTER(sgx_report_t),
            ctypes.c_int,
            ctypes.c_void_p,
        ]
        sgx_dcap_ql.sgx_qe_get_quote.restype = ctypes.c_int

        ret_val = ctypes.c_int(0)
        # Define structs required to be passed to fetch the report
        qe3_target = sgx_target_info_t()
        p_report = sgx_report_t()

        # Fetch target info by calling the respective sgx sdk function
        qe3_ret = sgx_dcap_ql.sgx_qe_get_target_info(ctypes.byref(qe3_target))
        if qe3_ret != 0:
            raise RuntimeError(
                f"sgx_qe_get_target_info return error code 0x{qe3_ret:04x}"
            )

        # Create Nonce object based on nonce input provided by user
        nonce_ptr = ctypes.create_string_buffer(nonce)

        # Call the report function
        status = self.report_function(
            self.eid,
            ctypes.byref(ret_val),
            ctypes.byref(qe3_target),
            nonce_ptr,
            len(nonce),
            ctypes.byref(p_report),
        )
        if status != 0:
            raise RuntimeError(f"Report callback returned error code {hex(status)}")
        if ret_val.value != 0:
            raise RuntimeError(f"Report retval returned error {hex(ret_val.value)}")
        # Quote size C native object
        quote_size = ctypes.c_int()

        # Fetch the quote size by calling the respective sgx sdk function
        qe3_ret = sgx_dcap_ql.sgx_qe_get_quote_size(ctypes.byref(quote_size))
        if qe3_ret != 0:
            raise RuntimeError(
                f"sgx_qe_get_quote_size return error code {hex(qe3_ret)}"
            )

        # Create a quote buffer object with the required quote size
        quote_buffer = ctypes.create_string_buffer(quote_size.value)

        # Fetch the sgx quote by calling the respective sgx sdk function
        qe3_ret = sgx_dcap_ql.sgx_qe_get_quote(
            ctypes.byref(p_report), quote_size.value, quote_buffer
        )
        if qe3_ret != 0:
            raise RuntimeError(f"sgx_qe_get_quote return error code {hex(qe3_ret)}")
        try:
            quote_data = base64.b64encode(
                bytearray(quote_buffer[: quote_size.value])
            ).decode("utf-8")
        except Exception as exc:
            log.error(f"Error while encoding data :{exc}")
            return None
        return Evidence(
            0, quote_data, None, self.user_data, None, const.INTEL_SGX_ADAPTER
        )
