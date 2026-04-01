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

# NVML device architecture constants (from nvml.h)
NVML_DEVICE_ARCH_KEPLER    = 2
NVML_DEVICE_ARCH_MAXWELL   = 3
NVML_DEVICE_ARCH_PASCAL    = 4
NVML_DEVICE_ARCH_VOLTA     = 5
NVML_DEVICE_ARCH_TURING    = 6
NVML_DEVICE_ARCH_AMPERE    = 7
NVML_DEVICE_ARCH_ADA       = 8
NVML_DEVICE_ARCH_HOPPER    = 9
NVML_DEVICE_ARCH_BLACKWELL = 10

# Supported architectures for confidential compute attestation
NVML_SUPPORTED_ARCHS = {NVML_DEVICE_ARCH_HOPPER, NVML_DEVICE_ARCH_BLACKWELL}

def arch_to_string(arch):
    """Maps an NVML device architecture integer to its lowercase string name."""
    arch_map = {
        NVML_DEVICE_ARCH_KEPLER:    "kepler",
        NVML_DEVICE_ARCH_MAXWELL:   "maxwell",
        NVML_DEVICE_ARCH_PASCAL:    "pascal",
        NVML_DEVICE_ARCH_VOLTA:     "volta",
        NVML_DEVICE_ARCH_TURING:    "turing",
        NVML_DEVICE_ARCH_AMPERE:    "ampere",
        NVML_DEVICE_ARCH_ADA:       "ada",
        NVML_DEVICE_ARCH_HOPPER:    "hopper",
        NVML_DEVICE_ARCH_BLACKWELL: "blackwell",
    }
    return arch_map.get(arch, "unknown")

class Error(Exception):
    """ Base class for other exceptions.
    """
    pass

class PynvmlError(Error):
    """ It is the base class for all exceptions related to pynvml.
    """
    pass

def generate_nvgpu_evidence(user_nonce):
    """Collects attestation evidence and certificate chain from all supported GPUs.

    Iterates over all available GPU devices, checks for confidential compute support,
    and retrieves attestation reports and certificates for each supported device.
    Only Hopper and Blackwell architectures are supported; unsupported devices cause
    an immediate error. The attestation report and certificate chain are base64-encoded
    and returned as a list of evidence dicts.
    """
    evidence_list = []
    try:
        nvmlInit()
        state = nvmlSystemGetConfComputeState()
        if state.ccFeature == 0:
            err_msg = "The confidential compute feature is disabled !!\nQuitting now."
            raise Error(err_msg)
        if state.devToolsMode != 0:
            log.warning("The system is running in CC DevTools mode !!")
        evidence_nonce = bytes.fromhex(user_nonce)
        number_of_available_gpus = nvmlDeviceGetCount()
        if number_of_available_gpus == 0:
            err_msg = "No NV GPU found ! \nQuitting now."
            raise Error(err_msg)

        for i in range(number_of_available_gpus):
            gpu_handle = nvmlDeviceGetHandleByIndex(i)

            device_arch = nvmlDeviceGetArchitecture(gpu_handle)
            if device_arch not in NVML_SUPPORTED_ARCHS:
                err_msg = f"Device at index {i} is not supported (arch={device_arch})"
                raise Error(err_msg)

            try:
                attestation_report_struct = nvmlDeviceGetConfComputeGpuAttestationReport(
                    gpu_handle, evidence_nonce)
                length_of_attestation_report = attestation_report_struct.attestationReportSize
                attestation_report = attestation_report_struct.attestationReport
                bin_attestation_report_data = bytes(
                    attestation_report[j] for j in range(length_of_attestation_report))
            except Exception as err:
                log.error(err)
                raise PynvmlError(
                    f"Something went wrong while fetching the attestation report from GPU {i}.")

            try:
                cert_struct = nvmlDeviceGetConfComputeGpuCertificate(gpu_handle)
                length_of_attestation_cert_chain = cert_struct.attestationCertChainSize
                attestation_cert_chain = cert_struct.attestationCertChain
                bin_attestation_cert_data = bytes(
                    attestation_cert_chain[j] for j in range(length_of_attestation_cert_chain))
            except Exception as err:
                log.error(err)
                raise PynvmlError(
                    f"Something went wrong while fetching the certificate chain from GPU {i}.")

            gpu_evidence = {
                'evidence':    base64.b64encode(bin_attestation_report_data).decode('utf-8'),
                'certificate': base64.b64encode(bin_attestation_cert_data).decode('utf-8'),
                'arch':        arch_to_string(device_arch),
            }
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
            # If ITA verifier nonce is used or user provides a nonce, transform it to 32-byte Hex string nonce (NVIDIA SDK accepts nonce in 32-byte Hex only)
            gpu_nonce = hashlib.sha256(nonce).hexdigest()
        else:
            # If nonce is not provided, generate random nonce in size of 32byte hex string
            gpu_nonce = secrets.token_bytes(32).hex()
        try:
            evidence_list = generate_nvgpu_evidence(gpu_nonce)
            if not evidence_list:
                log.error("No GPU evidence collected")
                return None
            log.debug("Collected GPU Evidence Successfully")
            log.debug(f"GPU Nonce : {gpu_nonce}")
            log.info(f"GPU Evidence count: {len(evidence_list)}")
        except Exception as e:
            log.exception(f"Caught Exception: {e}")
            return None

        # Build GPU evidence payload to be sent to Intel Trust Authority Service
        evidence_payload = self.build_payload(gpu_nonce, evidence_list)
        if evidence_payload is None:
            log.error("GPU Evidence not returned")
            return None

        gpu_evidence = Evidence(EvidenceType.NVGPU, evidence_payload, None, None)
        return gpu_evidence

    def build_payload(self, nonce, evidence_list):
        data = dict()
        data['nonce'] = nonce
        # Use the architecture from the first GPU
        data['arch'] = evidence_list[0]['arch']
        # Build the evidence_list with per-GPU evidence and certificate
        data['evidence_list'] = [
            {'evidence': e['evidence'], 'certificate': e['certificate']}
            for e in evidence_list
        ]

        try:
            payload = json.dumps(data)
        except TypeError as exc:
            log.error(f"Unable to serialize the data: {exc}")
            return None
        return payload

