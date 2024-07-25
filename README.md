# Intel Trust Authority Python Client 
Intel Trust Authority Client provides a set of Python modules for attesting different TEEs with Intel Trust Authority. Users can import the Python packages into their application and make REST calls to Intel Trust Authority for fetching token containing information about the TEE attested that can be verified.

## System Requirement

Use <b>Ubuntu 20.04</b>. 

## Installation
 
Install the latest version of the package with following commands:
 
Installation steps:
1) Install poetry using command `pip3 install --no-cache-dir poetry`
2) Create a wheel package:
    Spawn a poetry shell using command poetry shell:
    ```bash
    poetry shell
    ```
    Build wheel package inside shell using command poetry build:
    ```bash
    poetry build
    ```
3) Goto  dist folder where a whl package is created.
4) pip install <whl file name>. In this case it is applications_security_amber_trustauthority_client_for_python-0.1.0-py3-none-any.whl. inteltrustauthorityclient package is installed in site-packages:
    ```
    pip install <whl file name>
    ```

## Usage

If User has interface to get the quote/evidence and want to attest it with Intel Trust Authority:

Create a new Intel Trust Authority client, then use the exposed services to
access different parts of the Intel Trust Authority API.

### Create Connector instance.
```Python
#Create a config object that contains all parameters to connect to Intel Trust Authority and retry if there is 5XX error.
# base_url: Intel Trust Authority base url
# retry_cfg: Instance of RetryConfig class. Where retry_config has:
    # retry_wait_time_min: Minimum wait time between retries
    # retry_wait_time_max: Maximum wait time between retries
    # retry_max: Maximum number of Retries Allowed
    # timeout_sec: Request timeout in seconds
# api_url: Intel Trust Authority api url
# api_key: Intel Trust Authority api key

config_obj = config.Config(
            config.RetryConfig(
                int(retry_wait_time_min), int(retry_wait_time_max), int(retry_max), int(timeout_sec)
            ),
            trustauthority_base_url,
            trustAuthority_api_url,
            trust_authority_api_key,
        )

#object to the connector
ita_connector = connector.ITAConnector(config_obj)
```

### To get a Intel Trust Authority signed token with Nonce

- Create Adapter using:
    - **TDX**
        - [TDX](./inteltrustauthorityclient/tdx/README.md)
        - [Azure TDX](./inteltrustauthorityclient/tdx/azure/README.md)
    - **SGX**
        - [Intel SGX](./inteltrustauthorityclient/sgx/intel/README.md)


Use the adapter created with following piece of code to get attestation token:

```Python
# Generate the Attestation args instance
# adapter: Adapter object based on TEE
# trust_authority_request_id: Request id string
# policy_ids: List of policies to use in generating the token

attest_args = connector.AttestArgs(
            **adapter**, token_signing_algorithm, policy_must_match, trust_authority_request_id, policy_ids
        )

# Get the Attestation Token from Intel Trust Authority
attestation_token = ita_connector.attest(attest_args)
```

### To verify Intel Trust Authority signed token
```Python
#token: Attestation token returned by Intel Trust Authority

verified_token = connector.verify_token(token)
```

### To download token signing certificates from Intel Trust Authority
```
certs_data = connector.get_token_signing_certificates()
```

### For E2E token collection and signature verification logic refer
SGX: [SGX Sample App](./inteltrustauthorityclient/examples/sgx_sample_app/README.md)
TDX: [TDX Sample App](./inteltrustauthorityclient/examples/tdx_sample_app/README.md)


### Follow below link to run unit tests
[Unit Tests](./test/README.md) 

## License

This library is distributed under the BSD-style license found in the [LICENSE](./LICENSE)
file.
