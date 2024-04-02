"""
Copyright (c) 2023-2024 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""

TRUSTAUTHORITY_BASE_URL = "ENV_TRUSTAUTHORITY_BASE_URL"
TRUSTAUTHORITY_API_URL = "ENV_TRUSTAUTHORITY_API_URL"
TRUSTAUTHORITY_API_KEY = "ENV_TRUSTAUTHORITY_API_KEY"
TRUSTAUTHORITY_REQUEST_ID = "ENV_TRUSTAUTHORITY_REQUEST_ID"
TRUSTAUTHORITY_POLICY_ID = "ENV_TRUSTAUTHORITY_POLICY_ID"
RETRY_MAX = "ENV_RETRY_MAX"
RETRY_WAIT_TIME_MAX_SEC = "ENV_RETRY_WAIT_TIME_MAX"
RETRY_WAIT_TIME_MIN_SEC = "ENV_RETRY_WAIT_TIME_MIN"
DEFAULT_RETRY_WAIT_MIN_SEC = 2
DEFAULT_RETRY_WAIT_MAX_SEC = 2
DEFAULT_RETRY_MAX_NUM = 2
ATS_CERTCHAIN_MAXLENGTH = 10
HTTP_PROXY = "ENV_HTTP_PROXY"
HTTPS_PROXY = "ENV_HTTPS_PROXY"
INTEL_TDX_ADAPTER = "INTEL-TDX"
AZURE_TDX_ADAPTER = "AZURE-TDX"
GCP_TDX_ADAPTER = "GCP-TDX"
INTEL_SGX_ADAPTER = "INTEL-SGX"

# Intel Trust Authority URLs
NONCE_URL = "appraisal/v1/nonce"
AZURE_TDX_ATTEST_URL = "appraisal/v1/attest/azure/tdxvm"
INTEL_TDX_ATTEST_URL = "appraisal/v1/attest"

#GCP Specific
TDX_ATTEST_DEV_PATH = "/dev/tdx_guest"
REQ_BUF_SIZE = 4 * 4 * 1024
TD_REPORT_OFFSET = 32
TD_REPORT_SIZE = 1024
RUNTIME_DATA_SIZE_OFFSET = 1232
RUNTIME_DATA_OFFSET = 1236
IOC_WRITE = 1
IOC_READ = 2
IOC_NR_BITS = 8
IOC_TYPE_BITS = 8
IOC_SIZE_BITS = 14
IOC_NR_SHIFT = 0
IOC_TYPE_SHIFT = IOC_NR_SHIFT + IOC_NR_BITS
IOC_SIZE_SHIFT = IOC_TYPE_SHIFT + IOC_TYPE_BITS
IOC_DIR_SHIFT = IOC_SIZE_SHIFT + IOC_SIZE_BITS