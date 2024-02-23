"""
Copyright (c) 2024 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""

from src.base.evidence_adapter import EvidenceAdapter
from src.connector.evidence import Evidence

class AzureAdapter(EvidenceAdapter):
    """This class creates adapter which collects TDX Quote from TDX platform."""

    def __init__(self, user_data=None, event_log_parser=None) -> None:
        """Initializes tdx adapter object

        Args:
            user_data ([]byte): contains any user data to be added to Quote
            event_log_parser ([]byte):
        """
        self.user_data = user_data
        self.event_log_parser = event_log_parser
       
    def collect_evidence(self, nonce=None) -> Evidence:
        return None
    
    def ita_url():
        return {"get_nonce_url":"appraisal/v1/nonce","get_token_url":"/appraisal/v1/attest/azure/azure/tdxvm"}