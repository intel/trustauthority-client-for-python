# Intel® Trust Authority Python GCP TDX Adapter

Python package for collecting TDX Quote from GCP TDX enabled platform.

This TDX Adadpter is specifically built to work with Google Cloud TDX stack. It refers Google's [go-tdx-guest](https://github.com/google/go-tdx-guest/tree/main) for Quote generation. This tdx adapter is used with the [**connector**](../connector/) to request an attestation token and verify the same. 

## Requirements

- Use **Python 3.8 or newer**.

## Unit Tests
To run the tests, refer [Readme](../../../../test/).

## Usage

### To Create a new GCP TDX adapter, then use the adapter to collect quote from Google Cloud TDX enabled platform.

```python
#Create a new tdx adapter
adapter = GCPTDXAdapter(user_data, None)

#Use this adapter to get evidence
evidence = adapter.collect_evidence(nonce)
if evidence == None:
            return None #error condition
``

## License

This source is distributed under the BSD-style license found in the [LICENSE](../LICENSE)
file.