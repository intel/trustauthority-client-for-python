# Intel® Tiber™ Trust Authority Intel TDX Adapter

<p style="font-size: 0.875em;">· 05/21/2025 ·</p>

There are two types of Intel® Tiber™ Trust Authority adapters for Intel® Trust Domain Extensions (Intel® TDX) platforms:

1. An adapter for systems that use the configfs/TSM report subsystem to collect evidence for attestation. Supported platforms include bare-metal Intel TDX hosts and and Google Cloud Platform (GCP) confidential VMs with Intel TDX. The `./tdx` folder contains the Intel Trust Authority Intel TDX adapter for Intel TDX platforms.
2. An adapter for use with Microsoft Azure confidential VMs with Intel TDX. The `./tdx/azure` folder contains a the Intel Trust Authority Intel TDX adapter for Azure confidential VMs.


## Requirements

- Python 3.8 or newer
- Linux Kernel 6.7 or newer

## Unit Tests
To run the tests, refer [Readme](../../../test/README.md).

## Usage

To create a new Intel TDX adapter, then use the adapter to collect a quote (evidence):

```python
#Create a new tdx adapter
adapter = TDXAdapter(user_data)

#Use this adapter to get evidence
evidence = adapter.collect_evidence(nonce)
if evidence == None:
    return None #error condition
```

## License

This source is distributed under the BSD-style license found in the [LICENSE](../../../LICENSE)
file.

<br><br>
---

**\*** Other names and brands may be claimed as the property of others.