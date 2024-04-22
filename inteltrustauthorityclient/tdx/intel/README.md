# Intel® Trust Authority Python Intel TDX Adapter

Python package for collecting Quote from TDX enabled platform. This library leverages Intel [SGX DCAP](https://github.com/intel/SGXDataCenterAttestationPrimitives) for Quote generation. This Intel tdx adapter is used with the [**connector**](../../connector/) to request an attestation token and verify the same. 

## Requirements

- Use **Python 3.8 or newer**.

## Unit Tests
To run the tests, refer [Readme](../../../../test/).

## Usage

To Create a new Intel TDX adapter, then use the adapter to collect quote from Intel TDX enabled platform.

```python
#Create a new tdx adapter
adapter = TDXAdapter(user_data, event_log_parser)

#Use this adapter to get evidence
evidence = adapter.collect_evidence(nonce)
if evidence == None:
    return None #error condition
```

## License

This source is distributed under the BSD-style license found in the [LICENSE](../LICENSE)
file.