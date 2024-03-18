"""
Copyright (c) 2024 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""

import os
import hashlib
import fcntl
import ctypes
import base64

import logging as log
import inteltrustauthorityclient.src.resources.constants as const
from inteltrustauthorityclient.src.connector.evidence import Evidence
from inteltrustauthorityclient.src.base.evidence_adapter import EvidenceAdapter


class tdx_report_request(ctypes.Structure):
    _fields_ = [
        ("report_data", ctypes.c_uint8 * 64),
        ("td_report", ctypes.c_uint8 * 1024),
    ]


class tdx_quote_header(ctypes.Structure):
    _fields_ = [
        ("version", ctypes.c_uint64),
        ("status", ctypes.c_uint64),
        ("in_len", ctypes.c_uint32),
        ("out_len", ctypes.c_uint32),
        ("data", ctypes.c_uint8 * 16384),
    ]


class tdx_quote_request(ctypes.Structure):
    _fields_ = [("buffer", ctypes.POINTER(tdx_quote_header)), ("len", ctypes.c_uint64)]


class GCPTDXAdapter:
    """This class creates adapter which collects TDX Quote from GCP TDX platform."""

    def __init__(self, user_data=None, event_log_parser=None) -> None:
        """Initializes  gcp tdx adapter object

        Args:
            user_data ([]byte, optional): contains any user data to be added to Quote
            event_log_parser ([]byte, optional): 
        """
        self.user_data = user_data
        self.event_log_parser = event_log_parser

    def ioc(self, dir, t, nr, size):
        return (
            (dir << const.IOC_DIR_SHIFT)
            | (t << const.IOC_TYPE_SHIFT)
            | (nr << const.IOC_NR_SHIFT)
            | (size << const.IOC_SIZE_SHIFT)
        )

    def iowr(self, type, nr, size):
        return self.ioc(const.IOC_WRITE | const.IOC_READ, type, nr, size)

    def collect_evidence(self, nonce=None):
        """This Function calls the GCP TDX platform to perform I/O calls to get the TDX Quote.

        Args:
            nonce ([]byte]): optional nonce provided by Intel Trust Authority

        Returns:
            evidence: object to Evidence class containing quote
        """
        tdx_evidence = None  # Define the variable "tdx_evidence"
        # Get hash of nonce and user data
        if nonce != None or self.user_data != None:
            sha512_hash = hashlib.sha512()
            if nonce != None:
                sha512_hash.update(nonce)
            if self.user_data != None:
                sha512_hash.update((self.user_data.encode("utf-8")))
            digest = sha512_hash.digest()
        else:
            digest = bytearray(64)

        # Create a tdx_report_request object containing report
        try:
            td_request = tdx_report_request()
            ctypes.memmove(td_request.report_data, digest, len(digest))

            # Provide the digest and get td report from GCP TDX platform
            fd = os.open(const.TDX_ATTEST_DEV_PATH, os.O_RDWR)
            cmd = self.iowr(ord("T"), 1, ctypes.sizeof(tdx_report_request()))
            ioctl_result = fcntl.ioctl(fd, cmd, td_request)

            libc = ctypes.CDLL(None)
            # Create quote header structure to be passed to get quote
            tdx_quote_h = tdx_quote_header()
            tdx_quote_h.status = 0
            tdx_quote_h.version = 1
            tdx_quote_h.in_len = const.TD_REPORT_SIZE
            tdx_quote_h.out_len = 0
            libc.memcpy(
                tdx_quote_h.data,
                td_request.td_report,
                ctypes.sizeof(td_request.td_report),
            )

            # Get TDX Quote into tdx_request data structure. Basically tdx_quote_h.data will contain the quote.
            tdx_request = tdx_quote_request()
            tdx_request.buffer = ctypes.pointer(tdx_quote_h)
            tdx_request.len = const.REQ_BUF_SIZE
            cmd = self.iowr(ord("T"), 2, ctypes.sizeof(tdx_quote_request()))
            ioctl_result = fcntl.ioctl(fd, cmd, tdx_request)

            c_uint8_ptr = ctypes.cast(
                tdx_request.buffer.contents.data, ctypes.POINTER(ctypes.c_uint8)
            )
            #base64 encoding of quote
            quote = base64.b64encode(
                bytearray(c_uint8_ptr[: tdx_request.buffer.contents.out_len])
            ).decode("utf-8")

            runtime_data = base64.b64encode(self.user_data.encode()).decode("utf-8")
            # Create evidence class object to be returned
            tdx_evidence = Evidence(
                1, quote, None, runtime_data, None, const.GCP_TDX_ADAPTER
            )
        except AttributeError as e:
            log.error(f"An exception occurred: {str(e)}")
        except TypeError as e:
            log.error(f"An exception occurred: {str(e)}")
        except OSError as e:
            log.error(f"An exception occurred: {str(e)}")
        except ctypes.ArgumentError as e:
            log.error(f"An exception occurred: {str(e)}")
        except ValueError as e:
            log.error(f"An exception occurred: {str(e)}")
        except UnicodeDecodeError as e:
            log.error(f"An exception occurred: {str(e)}")
        except Exception as e:
            log.error(f"An exception occurred: {str(e)}")
        finally:
            log.info("Closing the file descriptor")
            os.close(fd)
            return tdx_evidence
