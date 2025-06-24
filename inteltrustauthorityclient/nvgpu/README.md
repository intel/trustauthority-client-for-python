# Intel® Tiber™ Trust Authority Python NVIDIA\* H100\* GPU Adapter

<p style="font-size: 0.875em;">· 05/21/2025 ·</p>

The Intel® Tiber™ Trust Authority Client for NVIDIA\* H100 GPU is a Python package for collecting evidence for attestation from a NVIDIA H100 GPU. This GPU adapter is used with the Intel Trust Authority [**connector**](../connector/README.md) for Python to request an attestation token and verify the same. 

This version of the GPU adapter works with Intel® Trust Domain Extensions (Intel® TDX) and NVIDIA H100 Confidential Computing platforms. 

The GPU adapter can be used to attest only a NVIDIA H100 GPU (or only the Intel TDX TEE), but the primary use case is a combined attestation of both the Intel TDX trust domain and the NVIDIA H100 GPU. The GPU adapter collects evidence from the GPU, and the Intel TDX adapter collects evidence from the trust domain. The connector combines the evidence from both adapters and sends it to Intel Trust Authority for verification. If successful, the response is an attestation token (JWT) that can be used to verify the integrity of the platform.

For more information, see [GPU Remote Attestation](https://docs.trustauthority.intel.com/main/articles/articles/ita/concept-gpu-attestation.html) in the Intel Trust Authority documentation.

## Requirements

The following prerequisites must be installed on the CVM (Confidential VM with Intel TDX):

- Use **Python 3.8 or newer**.
- Ubuntu 22.04 with *kernel 6.7 or later,* or Ubuntu 24.04. Support for the ConfigFS-TSM subsystem is required for Intel TDX attestation.
- NVIDIA H100 GPU
- NVIDIA Management Library (NVML). Install NVML by running the following command on the CVM after Python is installed: `pip install nvidia-ml-py`.

## Usage

To create a new NVIDIA GPU adapter and use the adapter to collect evidence from Intel TDX and NVIDIA H100 Condidential Computing enabled platform.

```python
#Create a new GPU adapter
adapter = GPUAdapter()

#Use this adapter to get evidence
evidence = adapter.collect_evidence(nonce)
if evidence == None:
    return None #error condition
```

## License

This source is distributed under the BSD-style license found in the [LICENSE](../../LICENSE)
file.

<br><br>
---

**\*** Other names and brands may be claimed as the property of others.
