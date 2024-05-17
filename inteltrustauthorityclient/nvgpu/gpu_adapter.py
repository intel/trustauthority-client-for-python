"""
Copyright (c) 2024 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""

import ctypes
import hashlib
import logging as log
import json
import secrets
import base64

from inteltrustauthorityclient.src.resources import constants as const
from inteltrustauthorityclient.src.base.evidence_adapter import EvidenceAdapter

log.disable(log.CRITICAL)

from nv_attestation_sdk import attestation
from nv_attestation_sdk.gpu import attest_gpu_remote

from dataclasses import dataclass

@dataclass
class GPUEvidence:
    type: str
    evidence: str
    user_data: str
    event_log: str

class GPUAdapter(EvidenceAdapter):
    def __init__(self, uData=None, evLogParser=None):
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

