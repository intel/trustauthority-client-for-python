# Intel® Trust Authority Python Azure TDX Adapter

Python package for collecting TDX Quote from MSFT Azure TDX enabled platform. This .py is specifically built to work with Azure TDX stack only. It leverages the TPM2 TSS library (specifically TSS2 ESYS APIs) and tpm2-tools for Quote generation. TPM2 TSS library: https://github.com/tpm2-software/tpm2-tss.

The TPM2 TSS library needs to be installed using [installation steps](https://github.com/tpm2-software/tpm2-tss/blob/master/INSTALL.md) in the build environment to build the adapter. This Azure tdx adapter is used with the [**connector**](../../connector/README.md) to request an attestation token and verify the same. 

## Requirements

- Use **Python 3.8 or newer**.

- ### Tools Requirement
    Please install tpm2-tools before using the library to generate quote.

    ```
    apt-get install tpm2-tools=4.1.1-1ubuntu0.20.04.1
    ```

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