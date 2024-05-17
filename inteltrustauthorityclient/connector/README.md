# Intel® Trust Authority Connector
Python Package for communicating with Intel Trust Authority via REST APIs

## System Requirement
Use <b>Ubuntu 20.04 or 22.04</b>.
## Usage

Create a new Connector instance, then use the exposed Functions to
access different parts of the Intel Trust Authority API.

```python
retryConfig_obj = RetryConfig()

// Initialize config required for connector using trustAuthorityBaseUrl, trustAuthorityApiUrl, trustAuthorityApiKey and retryConfig
config_obj = Config(trustauthority_base_url, retryConfig_obj, trustAuthority_api_url, trust_authority_api_key)

// Initialize TrustAuthorityConnector with the config
ita_connector = ITAConnector(config_obj)
```

### To attest and verify TEE with Intel Trust Authority using TEE Adapter
To create adapter refer:
- **TDX**
    - [Intel TDX](../tdx/intel/README.md)
    - [Azure TDX](../tdx/azure/README.md)
    - [GCP TDX](../tdx/gcp/README.md)
- **SGX**
    - [Intel SGX](../sgx/intel/README.md)

- **NVIDIA GPU**
    - [NVIDIA GPU](../nvgpu/README.md)
      
```python
// Initialize AttestArgs required for attestation
attest_args = AttestArgs(adapter , policy_ids, request_id)

// Invoke the attest API of the connector
attestation_token = ita_connector.attest(attest_args)

// Verify the received token
pub_key = ita_connector.verify_token(token)
```
