# Intel® Trust Authority TDX Adapter

Python package for collecting Quote from TDX enabled platform. This package leverages the TSM report subsytem for Quote generation. This tdx adapter is used with the [**connector**](../../connector/README.md) to request an attestation token and verify the same. 

## Requirements

- Use **Python 3.8 or newer**.

## Unit Tests
To run the tests, refer [Readme](../../../test/README.md).

## Usage

To Create a new TDX adapter, then use the adapter to collect quote from a TDX enabled platform.

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