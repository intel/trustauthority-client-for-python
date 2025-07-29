# Intel® Tiber™ Trust AuthorityPython Adapter for Azure Confidential VMs with Intel® TDX

<p style="font-size: 0.875em;">· 05/21/2025 ·</p>

There are two types of Intel® Tiber™ Trust Authority adapters for Intel® Trust Domain Extensions (Intel® TDX) platforms:

1. An adapter for systems that use the configfs/TSM report subsystem to collect evidence for attestation. Supported platforms include bare-metal Intel TDX hosts and and Google Cloud Platform (GCP) confidential VMs with Intel TDX. The `./tdx` folder contains the Intel Trust Authority Intel TDX adapter for Intel TDX platforms.
2. An adapter for use with Microsoft Azure\* confidential VMs with Intel TDX. The `./tdx/azure` folder contains a the Intel Trust Authority Intel TDX adapter for Azure confidential VMs.

This README is for the Microsoft Azure adapter, **azure-tdx-adapter.py**. It is specifically built to work with the Microsoft Azure implementation of the Intel TDX stack. The Azure adapter requires the TPM2 TSS library (specifically TSS2 ESYS APIs) and tpm2-tools to be installed on the TD for quote generation. For more information, see [TPM2 TSS library](https://github.com/tpm2-software/tpm2-tss).

The TPM2 TSS library must be installed in the build environment to build the adapter. For more information, see [TPM2 TSS library installation steps](https://github.com/tpm2-software/tpm2-tss/blob/master/INSTALL.md). 

## Requirements

- Python 3.8 or newer
- TPM2 TSS library

Install tpm2-tools on the Azure confidential VM with Intel TDX before using the adapter to generate a quote.

## Unit Tests
To run the tests, refer [Readme](../../../test/README.md).

## Usage

To Create a new Azure TDX adapter, then use the adapter to collect quote from Azure TDX enabled platform.

```python
#Create a new tdx adapter
adapter = AzureTDXAdapter(user_data)

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