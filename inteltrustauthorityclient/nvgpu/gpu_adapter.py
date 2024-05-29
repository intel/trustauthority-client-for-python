"""
Copyright (c) 2024 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""

import json
import base64
import secrets
import logging as log

from nv_attestation_sdk import attestation
from nv_attestation_sdk.gpu import attest_gpu_remote
from inteltrustauthorityclient.resources import constants as const
from inteltrustauthorityclient.base.evidence_adapter import EvidenceAdapter
from dataclasses import dataclass

@dataclass
class GPUEvidence:
    type: str
    evidence: bytearray

class GPUAdapter(EvidenceAdapter):
    def __init__(self):
        """Initializes GPU adapter object
        Args:
            user_data ([]byte): contains any user data to be added to Evidence (Currently not used for GPU)
            event_log_parser ([]byte): currently not used for GPU
        """

    def collect_evidence(self, nonce):
        # When Verifier nonce is not provided, generate the NV SDK compatible gpu_nonce of random 32 hex string 
        if nonce is None:
            nonce = secrets.token_bytes(32)
            
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
        gpu_evidence = GPUEvidence("H100", evidence_payload)
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

