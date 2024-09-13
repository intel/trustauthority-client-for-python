"""
Copyright (c) 2024 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""

from enum import Enum


class EvidenceType(Enum):
    """Enum for Evidence Type."""

    SGX, TDX, AZTDX, NVGPU = range(4)

    def __str__(self) -> str:
        if self == EvidenceType.SGX:
            return "sgx"
        elif self == EvidenceType.TDX:
            return "tdx"
        elif self == EvidenceType.AZTDX:
            return "aztdx"
        elif self == EvidenceType.NVGPU:
            return "nvgpu"
        else:
            return "unknown"


class Evidence:
    """Contains the attributes to be sent for attestation of platform."""

    def __init__(
        self,
        type: EvidenceType,
        evidence: bytearray,
        user_data: bytearray,
        runtime_data: bytearray,
    ) -> None:
        self._type = type
        self._evidence = evidence
        self._user_data = user_data
        self._runtime_data = runtime_data

    @property
    def type(self):
        """Getter method."""
        return self._type

    @property
    def evidence(self):
        return self._evidence

    @property
    def user_data(self):
        """Getter method."""
        return self._user_data

    @property
    def runtime_data(self):
        """Getter method."""
        return self._runtime_data
