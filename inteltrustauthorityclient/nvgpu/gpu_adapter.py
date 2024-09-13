"""
Copyright (c) 2024 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""

import json
import base64
import secrets
import hashlib
import logging as log
from nv_attestation_sdk.gpu import attest_gpu_remote
from inteltrustauthorityclient.resources import constants as const
from inteltrustauthorityclient.base.evidence_adapter import EvidenceAdapter
from inteltrustauthorityclient.connector.evidence import Evidence, EvidenceType

class GPUAdapter(EvidenceAdapter):
    def __init__(self):
        """Initializes GPU adapter object
        """

    def collect_evidence(self, nonce):
        if nonce != None:
            # If ITA verifier nonce is used or user provides a nonce, transform it to 32-byte Hex string nonce (NVDIA SDK accepts nonce in 32-byte Hex only )
            gpu_nonce = hashlib.sha256(nonce).hexdigest()
        else:
            # If nonce is not provided, generate random nonce in size of 32byte hex string
            gpu_nonce = secrets.token_bytes(32).hex()
        try:
           evidence_list = attest_gpu_remote.generate_evidence(gpu_nonce)
           # Only single GPU attestaton is supported for now.
           raw_evidence = evidence_list[0] 
           log.debug("Collected GPU Evidence Successfully")
           log.debug("GPU Nonce : {gpu_nonce}")
           log.info(f"GPU Evidence : {raw_evidence}")
        except Exception as e:
           log.exception(f"Caught Exception: {e}")
           return None
        
        # Build GPU evidence payload to be sent to Intel Trust Authority Service 
        evidence_payload = self.build_payload(gpu_nonce, raw_evidence['attestationReportHexStr'], raw_evidence['certChainBase64Encoded'])
        if evidence_payload is None:
            log.error("GPU Evidence not returned")
            return None

        gpu_evidence = Evidence(EvidenceType.NVGPU, evidence_payload, None, None)
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

