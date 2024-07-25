"""
Copyright (c) 2024 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""

import base64
import requests
import time
import json
import io
import subprocess
import struct
import hashlib
import tempfile
import os
import binascii

import logging as log
import inteltrustauthorityclient.resources.constants as const
from inteltrustauthorityclient.connector.evidence import Evidence
from inteltrustauthorityclient.base.evidence_adapter import EvidenceAdapter

TD_REPORT_OFFSET = 32
TD_REPORT_SIZE = 1024
RUNTIME_DATA_SIZE_OFFSET = 1232
RUNTIME_DATA_OFFSET = 1236


class AzureTDXAdapter:
    """This class creates adapter which collects TDX Quote from Azure TDX platform."""

    def __init__(self, user_data: bytearray = None) -> None:
        """Initializes azure tdx adapter object

        Args:
            user_data (_type_, optional): _description_. Defaults to None.
        """
        self.user_data = user_data

    def collect_evidence(self, nonce=None) -> Evidence:
        """This Function calls tpm2-tools to get Azure TDX quote.

        Args:
            nonce ([]byte]): optional nonce provided

        Returns:
            evidence: object to Evidence class
        """
        if nonce != None or self.user_data != None:
            sha512_hash = hashlib.sha512()
            if nonce != None:
                sha512_hash.update(nonce)
            if self.user_data != None:
                sha512_hash.update(self.user_data)
            digest = sha512_hash.digest()
        else:
            digest = bytearray(64)

        # Check if tpm2_nvreadpublic 0x01400002 is defined
        # If not then define it
        command = ["tpm2_nvreadpublic", "0x01400002"]
        try:
            subprocess.run(command, check=True, stdout=subprocess.DEVNULL)
        except Exception as e:
            log.info("Creating nv_index as it is not defined already")
            try:
                command = ["tpm2_nvdefine", "-C", "o", "0x01400002", "-s", "64"]
                subprocess.run(command, check=True)
            except subprocess.CalledProcessError as e:
                log.error(f"issue in creating nv_index: {e}")
                return None
            except Exception as e:
                log.error(f"issue in creating nv_index: {e}")
                return None

        # Write sha512(nonce || user_data) to NVIndex : "tpm2_nvwrite", "-C", "o", "0x1400002", "-i", "-"
        try:
            with tempfile.NamedTemporaryFile(mode="wb", delete=False) as temp_file:
                temp_filename = temp_file.name
                temp_file.write(digest)
            command = ["tpm2_nvwrite", "-C", "o", "0x01400002", "-i", temp_filename]
            result = subprocess.run(command, check=True)
        except subprocess.CalledProcessError as e:
            log.error(f"issue in writing to nv_index: {e}")
            return None
        except Exception as e:
            log.error(f"issue in writing to nv_index {e}")
            return None
        finally:
            temp_file.close()

        time.sleep(3)
        # Read the final report at "0x01400001"
        try:
            command = ["tpm2_nvread", "-C", "o", "0x01400001"]
            result = subprocess.run(command, capture_output=True)
            tpm_report = result.stdout
        except subprocess.CalledProcessError as e:
            log.error(f"error while reading TDReport from NVIndex.: {e}")
            return None
        except Exception as e:
            log.error(f"error while reading TDReport from NVIndex. {e}")
            return None

        td_report = tpm_report[TD_REPORT_OFFSET : TD_REPORT_OFFSET + TD_REPORT_SIZE]

        # give the report to azure as input to get the quote
        payload = base64.b64encode(td_report).decode("utf-8")
        # send report to Azure
        url = "http://169.254.169.254/acc/tdquote"
        headers = {"Content-Type": "application/json"}
        body = {"report": payload}
        payload_json = json.dumps(body)
        timeout_sec = (
            const.DEFAULT_CLIENT_TIMEOUT_SEC
            if os.getenv("CLIENT_TIMEOUT_SEC") is None
            else os.getenv("CLIENT_TIMEOUT_SEC")
        )
        try:
            response = requests.post(
                url, data=payload_json, headers=headers, timeout=timeout_sec
            )
        except requests.HTTPError as e:
            log.error(f"got http error: {e.code} {e.reason}")
            return None
        except Exception as e:
            log.error(f"got error in post request: {e}")
            return None
        resp_quote = response.json()
        quote = resp_quote.get("quote")
        r_size = struct.unpack(
            "<I", tpm_report[RUNTIME_DATA_SIZE_OFFSET:RUNTIME_DATA_OFFSET]
        )[0]
        runtime_data = tpm_report[RUNTIME_DATA_OFFSET : RUNTIME_DATA_OFFSET + r_size]

        if nonce != None and self.user_data != None:
            try:
                runtime_data_map = json.loads(runtime_data)
            except json.JSONDecodeError as e:
                log.error(f"Invalid runtime_data: {e}")
                return None

            if "user-data" not in runtime_data_map:
                log.error("runtime_data doesn't include user-data")
                return None

            user_data = runtime_data_map["user-data"]

            if not isinstance(user_data, str):
                log.error("user-data string assertion fail")
                return None

            if user_data.lower() != binascii.hexlify(digest).decode().lower():
                log.error("The collected evidence is invalid")
                return None

        # Create evidence class object to be returned
        tdx_evidence = Evidence(1, quote, self.user_data, runtime_data)
        return tdx_evidence
