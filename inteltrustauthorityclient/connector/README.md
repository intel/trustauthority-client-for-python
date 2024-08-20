# Intel® Trust Authority Client Connector for Python

<p style="font-size: 0.875em;">· 08/14/2024 ·</p> 

The Intel® Trust Authority Client Connector for Python is a library of Python modules used to perform remote attestation of a Trusted Execution Environment (TEE) using Intel Trust Authority as the verifier. The "connector" (as we call it) is an interface for the Intel Trust Authority REST API. The process logic for attestation and verification is implemented in the Intel Trust Authority service, not in the connector. The connector is a client that sends requests to the Intel Trust Authority service and processes the responses.

The **ITAConnector** class includes the following methods for attestation and verification:

  [**`attest`**](https://docs.trustauthority.intel.com/main/articles/integrate-python-client.html#attest)<br> Collects evidence and requests an attestation token from Intel Trust Authority for clients using a Passport validation model.

  [**`get_nonce`**](https://docs.trustauthority.intel.com/main/articles/integrate-python-client.html#get_nonce)<br> Gets a nonce and parses it to JSON.

  [**`get_token`**](https://docs.trustauthority.intel.com/main/articles/integrate-python-client.html#get_token)<br> Requests an attestation token from Intel Trust Authority. `get_token` Provides more control than `attest` by allowing a confidential app to include user data, provide a nonce, and modify evidence structures before requesting a token. `get_token` supports both Passport and Background-check attestation models.

  [**`get_token_signing_certificates`**](https://docs.trustauthority.intel.com/main/articles/integrate-python-client.html#get_token_signing_certificates)<br> Retrieves a JSON Web Key Set (JWKS) that contains the collection of signing certificates used by Intel Trust Authority to sign attestation tokens.

  [**`verify_token`**](https://docs.trustauthority.intel.com/main/articles/integrate-python-client.html#verify_token)<br> Verifies that an Intel Trust Authority attestation token is properly formatted and signed. 

A connector requires a TEE adapter (`adapter: EvidenceAdapter` in **AttestArgs**) to collect evidence from the attesting platform. However, a relying party can use the connector to verify a token or perform a background-check attestation without a TEE adapter. The only ITAConnector method that requires a TEE adapter is **attest**.

To collect evidence from a TEE without requesting attestation, such as for background-check attestation, development, or validation, use the TEE adapter's **collect_evidence** method directly.

## Usage

Follow this basic workflow, modifying it as necessary for your use case:

1. Install the library from a wheel package as described in the main README [installation section](https://github.com/intel/trustauthority-client-for-python/tree/main#installation).
1. Import the required modules into your application. For examples of minimal imports, see the sample applications in the [examples](./inteltrustauthorityclient/examples) folder.
1. Create an **ITAConnector.config** object and set the required properties: Intel Trust Authority _base URL_**\*\***, _API URL_**\*\***, _API key_, and _retry configuration_. 
1. Create an ITAConnector object with the config object.
1. If you need to collect evidence from the TEE, you'll need to create an adapter object of the correct type for your TEE. `attest` requires an adapter object in **AttestArgs**, and `collect_evidence` is a method of the adapter object.
1. Use the connector object (and adapter object, if required) to call the desired method.

For more information, see the [Python Connector Reference](https://docs.trustauthority.intel.com/main/articles/integrate-python-client.html) in the Intel Trust Authority documentation. Also see the sample applications in the [examples](./inteltrustauthorityclient/examples) folder. 

<br><br>
---

**\*\*** Intel Trust Authority subscription region determines the base URL you must use. In the European Union region, the base URL is `https://portal.eu.trustauthority.intel.com`, and the API URL is `https://api.eu.trustauthority.intel.com`. <br> For subscriptions outside the EU, the base URL is `https://portal.trustauthority.intel.com`, and the API URL is `https://api.trustauthority.intel.com`. Subscriptions, URLs, and API keys are region-specific. 
