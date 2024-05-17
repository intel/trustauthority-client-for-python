# Intel® Trust Authority Python NVIDIA GPU Adapter

Python package for collecting GPU Evidence from Confidential Computing enabled platform with Intel TDX and NVIDIA H100 GPU. This library leverages NVIDIA Attestation SDK (https://github.com/NVIDIA/nvtrust/tree/main/guest_tools/attestation_sdk) for H100 GPU Evidence generation). This Intel gpu adapter is used with the [**connector**](../../connector/README.md) to request an attestation token and verify the same. 

## Requirements

- Use **Python 3.8 or newer**.

## Unit Tests
To run the tests, refer [Readme](../../../test/README.md).

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

This source is distributed under the BSD-style license found in the [LICENSE](../../../LICENSE)
file.
