"""
Copyright (c) 2024-2025 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""

import json
import base64
import secrets
import hashlib
import logging as log
from inteltrustauthorityclient.resources import constants as const
from inteltrustauthorityclient.base.evidence_adapter import EvidenceAdapter
from inteltrustauthorityclient.connector.evidence import Evidence, EvidenceType
from pynvml import (
    nvmlInit,
    nvmlDeviceGetArchitecture,
    nvmlDeviceGetCount,
    nvmlDeviceGetHandleByIndex,
    nvmlShutdown,
    nvmlSystemGetDriverVersion,
    nvmlDeviceGetConfComputeGpuAttestationReport,
    nvmlDeviceGetConfComputeGpuCertificate,
    nvmlSystemSetConfComputeGpusReadyState,
    nvmlSystemGetConfComputeGpusReadyState,
    nvmlSystemGetConfComputeState,
)

class Error(Exception):
    """ Base class for other exceptions.
    """
    pass

class PynvmlError(Error):
    """ It is the base class for all exceptions related to pynvml.
    """
    pass

def generate_nvgpu_evidence(user_nonce):
    evidence_list = []
    try:
        nvmlInit()
        state = nvmlSystemGetConfComputeState()
        print(state.ccFeature)
        if state.ccFeature == 0:
            print("WARNING: state.ccFeature = 0 (disabled), but library needs PPCIE support")
            #err_msg = "The confidential compute feature is disabled !!\nQuitting now."
            #raise Error(err_msg)
        if state.devToolsMode != 0:
            log.warning("The system is running in CC DevTools mode !!")
        evidence_nonce = bytes.fromhex(user_nonce)
        number_of_available_gpus = nvmlDeviceGetCount()
        if number_of_available_gpus == 0:
            err_msg = "No NV GPU found ! \nQuitting now."
            raise Error(err_msg)
        #if number_of_available_gpus > 1:
        #    log.warning("There are more than one NVGPU found, but only the first one used")

        for gpu_index in range(number_of_available_gpus):
            print("gathering report for gpu index %d" % gpu_index)
            gpu_handle = nvmlDeviceGetHandleByIndex(gpu_index)

            try:
                attestation_report_struct = nvmlDeviceGetConfComputeGpuAttestationReport(gpu_handle,
                                                                                        evidence_nonce)
                length_of_attestation_report = attestation_report_struct.attestationReportSize
                attestation_report = attestation_report_struct.attestationReport
                attestation_report_data = list()

                for i in range(length_of_attestation_report):
                    attestation_report_data.append(attestation_report[i])

                bin_attestation_report_data = bytes(attestation_report_data)
            except Exception as err:
                log.error(err)
                err_msg = "Something went wrong while fetching the attestation report from the gpu."
                raise PynvmlError(err_msg)

            try:
                cert_struct = nvmlDeviceGetConfComputeGpuCertificate(gpu_handle)
                # fetching the attestation cert chain.
                length_of_attestation_cert_chain = cert_struct.attestationCertChainSize
                attestation_cert_chain = cert_struct.attestationCertChain
                attestation_cert_data = list()

                for i in range(length_of_attestation_cert_chain):
                    attestation_cert_data.append(attestation_cert_chain[i])

                bin_attestation_cert_data = bytes(attestation_cert_data)

            except Exception as err:
                log.error(err)
                err_msg = "Something went wrong while fetching the certificate chains from the gpu."
                raise PynvmlError(err_msg)

            gpu_evidence = {'certChainBase64Encoded': base64.b64encode(bin_attestation_cert_data),
                            'attestationReportHexStr': bin_attestation_report_data.hex()}
            evidence_list.append(gpu_evidence)

        nvmlShutdown()
    except Exception as error:
        log.error(error)
    finally:
        return evidence_list

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
           evidence_list = generate_nvgpu_evidence(gpu_nonce)
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
        data['certificate'] = cert_chain.decode('utf-8')

        try:
            payload = json.dumps(data)
        except TypeError as exc:
            log.error(f"Unable to serialize the data: {exc}")
            return None
        return payload

