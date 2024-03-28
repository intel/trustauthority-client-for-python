# Intel® Trust Authority Python Intel SGX Adapter

The **tdx/intel** adapter enables a confidential confidential computing client to collect a quote from an Intel SGX enclave for attestation by Intel Trust Authority. The Intel sgx adapter is used with the [**connector**](../../connector/) to request an attestation token. 

## Requirements

- Use **Python 3.8 or newer**.
- Intel® SGX DCAP for quote generation. For more information, see https://github.com/intel/SGXDataCenterAttestationPrimitives

## Unit Tests
To run the tests, refer [Readme](../../../../test/).

## Usage

### To Create a new Intel SGX adapter and use it to get evidence.

**SGXAdapter()** accepts one optional argument: **tdHeldData**, and **EventLogParser**. **tdHeldData**  is binary data provided by the client. tdHeldData, if provided, is output to the **attester_held_data** claim in the attestation token.

**collect_evidence()** requires a **nonce** argument. A SHA512 hash is calculated for the nonce and tdHeldData (if any) and saved in the TD quote REPORTDATA field. If successful, collect_evidence() returns a TD quote that's formatted for attestation by Intel Trust Authority.

```python
#Create a new tdx adapter
adapter = SGXAdapter(user_data, None)

#Use this adapter to get evidence
evidence = adapter.collect_evidence(nonce)
if evidence == None:
            return None #error condition
``

## License

This source is distributed under the BSD-style license found in the [LICENSE](../LICENSE)
file.