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
from inteltrustauthorityclient.connector.evidence import * 

class GPUAdapter(EvidenceAdapter):
    def __init__(self):
        """Initializes GPU adapter object
        """

    def collect_evidence(self, nonce):
        # When Verifier nonce is not provided, generate the NV SDK compatible gpu_nonce of random 32 hex string 
        if nonce is None:
            # Generating random nonce in size of 32byte hex string
            nonce = secrets.token_bytes(32).hex()
            
        try:
           evidence_list = attest_gpu_remote.generate_evidence(nonce)
           # Only one GPU attestaton is supported for now.
           raw_evidence = evidence_list[0] 
           log.info("Collected GPU Evidence Successfully")
           log.info(f"GPU Evidence : {raw_evidence}")
        except Exception as e:
           log.exception(f"Caught Exception: {e}")
           return None
        
        # Build GPU evidence payload to be sent to NRAS, with nonce, Attestation Report, Certificate extracted from the Raw GPU evidence 
        evidence_payload = self.build_payload(nonce, raw_evidence['attestationReportHexStr'], raw_evidence['certChainBase64Encoded'])
        if evidence_payload is None:
            log.error("GPU Evidence not returned")
            return None

        gpu_evidence = GPUEvidence("H100", evidence_payload, const.NV_GPU_ADAPTER)
        return gpu_evidence

    def build_payload(self, nonce, evidence, cert_chain):
        data = dict()
        data['nonce'] = nonce

        try:
            encoded_evidence_bytes = evidence.encode("ascii")
            encoded_evidence = base64.b64encode(encoded_evidence_bytes)
            encoded_evidence = encoded_evidence.decode('utf-8')
        except Exception as exc:
            log.error(f"Error while encoding data :{exc}")
            return None

        data['evidence'] = encoded_evidence
        data['arch'] = 'HOPPER'
        data['certificate'] = str(cert_chain)

        try:
            payload = json.dumps(data)
        except TypeError as exc:
            log.error(f"Unable to serialize the data: {exc}")
            return None
        return payload

