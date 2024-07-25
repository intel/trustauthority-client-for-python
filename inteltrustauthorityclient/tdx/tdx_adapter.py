"""
Copyright (c) 2024 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""

import base64
import hashlib
import logging as log


from inteltrustauthorityclient.connector.evidence import Evidence, EvidenceType
from inteltrustauthorityclient.base.evidence_adapter import EvidenceAdapter
from inteltrustauthorityclient.configfs_tsm.report import *


class TDXAdapter(EvidenceAdapter):
    """This class creates adapter which collects quote using configfs-tsm."""

    def __init__(self, user_data: bytearray = None) -> None:
        """Initializes tdx adapter object

        Args:
            user_data (bytearray): contains any user data to be added to Quote
        """
        self.user_data = user_data

    def collect_evidence(self, nonce=None) -> Evidence:
        """This Function checks the linux subsytem to collect quote using configfs-tsm

        Args:
            nonce ([]byte]): optional nonce provided

        Returns:
            evidence: object to Evidence class
        """

        evidence = None
        td_quote = None
        sha512_hash = hashlib.sha512()
        # Get hash of nonce and user data
        if nonce != None or self.user_data != None:
            if nonce != None:
                sha512_hash.update(nonce)
            if self.user_data != None:
                sha512_hash.update(self.user_data)

        digest = sha512_hash.digest()
        request_instance = Request(digest, False)
        report = Report()
        try:
            response = report.get_report(request_instance)
            if response is None:
                log.error(f"Failed to fetch quote using Configfs TSM.")
                return None

            td_quote = response.out_blob
        except Exception as e:
            log.error(f"Failed to fetch quote using Configfs TSM. Error: {e}")
            return None

        if td_quote is not None:
            quote = base64.b64encode(bytearray(td_quote)).decode("utf-8")
            runtime_data = self.user_data
            # Create evidence class object to be returned
            evidence = Evidence(EvidenceType.TDX, quote, None, runtime_data)
        else:
            log.error(f"Failed to get response from Configfs TSM.")
            return None
        return evidence
