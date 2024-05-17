"""
Copyright (c) 2024 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""

import json
import base64
import logging as log

from nv_attestation_sdk import attestation
from nv_attestation_sdk.gpu import attest_gpu_remote
from inteltrustauthorityclient.resources import constants as const
from inteltrustauthorityclient.base.evidence_adapter import EvidenceAdapter
from dataclasses import dataclass

log.disable(log.CRITICAL)

@dataclass
class GPUEvidence:
    type: str
    evidence: bytearray
    user_data: bytearray
    event_log: bytearray
#class GPUEvidence:
#    type: str
#    evidence: str
#    user_data: str
#    event_log: str

class GPUAdapter(EvidenceAdapter):
    def __init__(self, uData=None, evLogParser=None):
        """Initializes GPU adapter object
        Args:
            user_data ([]byte): contains any user data to be added to Evidence (Currently not used)
            event_log_parser ([]byte):
        """
        self.uData = uData
        self.EvLogParser = evLogParser

    def collect_evidence(self, nonce):
        try:
           evidence_list = attest_gpu_remote.generate_evidence(nonce)
           # Only one GPU attestaton support for now.
           raw_evidence = evidence_list[0] 
           log.info("Collected GPU Evidence Successfully")
           log.info(f"GPU Evidence : {raw_evidence}")
        except Exception as e:
           log.exception(f"Caught Exception: {e}")
           return None

        evidence_payload = self.build_payload(nonce, raw_evidence['attestationReportHexStr'], raw_evidence['certChainBase64Encoded'])
        # Currently GPU attestation does not use user data. 
        gpu_evidence = GPUEvidence("H100", evidence_payload, user_data=None, event_log=None)
        return gpu_evidence

    def build_payload(self, nonce, evidence, cert_chain):
        data = dict()
        data['nonce'] = nonce
        encoded_evidence_bytes = evidence.encode("ascii")
        encoded_evidence = base64.b64encode(encoded_evidence_bytes)
        encoded_evidence = encoded_evidence.decode('utf-8')
        data['evidence'] = encoded_evidence
        data['arch'] = 'HOPPER'
        data['certificate'] = str(cert_chain)
        payload = json.dumps(data)
        return payload

