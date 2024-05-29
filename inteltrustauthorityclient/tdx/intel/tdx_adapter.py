"""
Copyright (c) 2024 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""

import ctypes
import base64
import hashlib
import logging as log

from inteltrustauthorityclient.resources import constants as const
from inteltrustauthorityclient.connector.evidence import Evidence
from inteltrustauthorityclient.base.evidence_adapter import EvidenceAdapter


class tdx_report_data_t(ctypes.Structure):
    _fields_ = [("d", ctypes.c_uint8 * 64)]


class tdx_uuid_t(ctypes.Structure):
    _fields_ = [("d", ctypes.c_uint8 * 16)]


class TDXAdapter(EvidenceAdapter):
    """This class creates adapter which collects TDX Quote from Intel TDX platform."""

    def __init__(self, user_data: bytearray=None, event_log_parser: bytearray=None) -> None:
        """Initializes tdx adapter object

        Args:
            user_data (bytearray): contains any user data to be added to Quote
            event_log_parser (bytearray): contains event log parser
        """
        self.user_data = user_data
        self.event_log_parser = event_log_parser

    def collect_evidence(self, nonce=None) -> Evidence:
        """This Function calls DCAP libraries to get TDX quote.

        Args:
            nonce ([]byte]): optional nonce provided

        Returns:
            evidence: object to Evidence class
        """
        try:
            # Load the TDX Attestation library
            c_lib = ctypes.CDLL("libtdx_attest.so")
        except FileNotFoundError as e:
            log.exception(
                f"Caught Exception in loading the libtdx_attest.so library: {e}"
            )
            return None
        except OSError as e:
            log.exception(
                f"Caught Exception in loading the libtdx_attest.so library: {e}"
            )
            return None
        except Exception as e:
            log.exception(
                f"Caught Exception in loading the libtdx_attest.so library: {e}"
            )
            return None

        try:
            tdx_att_get_quote = (
                c_lib.tdx_att_get_quote
            )  # tdx_att_get_quote is C function to be called
            tdx_report = tdx_report_data_t()
            if nonce != None:
                sha512_hash = hashlib.sha512()
                sha512_hash.update(nonce)
                if self.user_data != None:
                    sha512_hash.update((self.user_data))
                digest = sha512_hash.digest()
                for i in range(len(digest)):
                    tdx_report.d[i] = digest[i]

            tdx_uuid = tdx_uuid_t()
            quote_buffer = ctypes.POINTER(ctypes.c_uint8)()
            quote_size = ctypes.c_uint32(0)

            tdx_att_get_quote.argtypes = [
                ctypes.POINTER(tdx_report_data_t),
                ctypes.POINTER(tdx_uuid_t),
                ctypes.c_uint32,
                ctypes.POINTER(tdx_uuid_t),
                ctypes.POINTER(ctypes.POINTER(ctypes.c_uint8)),
                ctypes.POINTER(ctypes.c_uint32),
                ctypes.c_uint32,
            ]

            tdx_att_get_quote.restype = ctypes.c_int

            # Call the tdx_att_get_quote function
            result = c_lib.tdx_att_get_quote(
                ctypes.byref(tdx_report),
                None,
                0,
                tdx_uuid,
                ctypes.byref(quote_buffer),
                ctypes.byref(quote_size),
                0,
            )

            # Check the result
            if result != 0:
                log.error(f"tdx_att_get_quote failed with result {hex(result)}")
                return None

            # Fetch the quote from pointer passed to c library
            c_uint8_ptr = ctypes.cast(quote_buffer, ctypes.POINTER(ctypes.c_uint8))
            quote = base64.b64encode(bytearray(c_uint8_ptr[: quote_size.value])).decode(
                "utf-8"
            )
            # Free the tdx quote from c memory
            ret = c_lib.tdx_att_free_quote(quote_buffer)
            if ret != 0:
                log.error(f"Error: tdx_att_free_quote failed with result {hex(ret)}")
            log.info("Quote : %s", quote)
            runtime_data = self.user_data
            # Create evidence class object to be returned
            tdx_evidence = Evidence(
                1, quote, None, runtime_data, None, const.INTEL_TDX_ADAPTER
            )
            return tdx_evidence

        except MemoryError as e:
            log.exception(f"Caught Exception in: {e}")
            return None
        except AttributeError as e:
            log.exception(f"Caught Exception in: {e}")
            return None
        except ValueError as e:
            log.exception(f"Caught Exception in: {e}")
            return None
        except ctypes.ArgumentError as e:
            log.exception(f"Caught Exception in: {e}")
            return None
        except RuntimeError as e:
            log.exception(f"Caught Exception in calling function: {e}")
            return None
        except Exception as e:
            log.exception(f"Caught Exception: {e}")
            return None
