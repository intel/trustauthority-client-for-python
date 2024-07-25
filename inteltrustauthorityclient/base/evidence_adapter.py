"""
Copyright (c) 2024 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""

from abc import ABC, abstractmethod
from inteltrustauthorityclient.connector.evidence import Evidence


class EvidenceAdapter(ABC):
    """Abstract class to be inherited by adapter implementation subclasses.

    Args:
        ABC (Abstract class object): Helper class that provides a standard way to create an ABC using inheritance.
    """

    @abstractmethod
    def collect_evidence(self, nonce) -> Evidence:
        pass
