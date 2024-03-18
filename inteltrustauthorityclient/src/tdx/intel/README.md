# Intel® Trust Authority Python TDX Adapter

The **tdx/azure** adapter enables a confidential computing client running in an Azure tdx domain to collect a quote for attestation by Intel Trust Authority. The azure tdx adapter is used with the [**connector**](../../connector/) to request an attestation token. 

## Requirements

- Use **Python 3.8 or newer**.

## Unit Tests
#TODO: Run the commands for this
To run the tests, run ``. See the example test in `` for an example of a test.

## Usage

### To Create a new Azure TDX adapter and use it to get evidence.

**AzureTDXAdapter()** and then use the adapter to collect a quote from a TD. AzureTDXAdapter() accepts one optional argument: **tdHeldData**, and **EventLogParser**. **tdHeldData**  is binary data provided by the client. tdHeldData, if provided, is output to the **attester_held_data** claim in the attestation token.

**collect_evidence()** requires a **nonce** argument. A SHA512 hash is calculated for the nonce and tdHeldData (if any) and saved in the TD quote REPORTDATA field. If successful, collect_evidence() returns a TD quote that's formatted for attestation by Intel Trust Authority.

```python
#Create a new tdx adapter
adapter = AzureTDXAdapter(user_data, None)

#Use this adapter to get evidence
evidence = adapter.collect_evidence(nonce)
if evidence == None:
            return None #error condition
``

## License

This source is distributed under the BSD-style license found in the [LICENSE](../LICENSE)
file.