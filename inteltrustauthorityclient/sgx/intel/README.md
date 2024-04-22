# Intel® Trust Authority Python SGX Adapter

The **sgx/intel** adapter enables a confidential confidential computing client to collect a quote from an SGX enclave for attestation by Intel Trust Authority. This sgx adapter is used with the [**connector**](../../connector/README.md) to request an attestation token and verify the same. 

## Requirements

- Use **Python 3.8 or newer**.
- Intel® SGX DCAP for quote generation. For more information, see https://github.com/intel/SGXDataCenterAttestationPrimitives

## Unit Tests
To run the tests, refer [Readme](../../../test/README.md).

## Usage

To Create a new SGX adapter, then use the adapter to collect quote from SGX enabled platform.

```python
#Create a new sgx adapter
# enclave_id: SGX Enclave id
# report_function: Callback Report function to get Enclave Report Data.
    ## returns: SGX Enclave Report Data
adapter = SGXAdapter(enclave_id, report_function, user_data)

#Use this adapter to get evidence
evidence = adapter.collect_evidence(nonce)
if evidence == None:
    return None #error condition
```

## License

This source is distributed under the BSD-style license found in the [LICENSE](../../../LICENSE)
file.