# Intel Trust Authority Python Client 
Intel Trust Authority Client provides a set of Python modules for attesting different TEEs with Intel Trust Authority. You can import the Python packages into your application for Intel® TDX attestation from your application or workflow.

## System Requirement

Use <b>Ubuntu 20.04</b>. 

## Installation

Install the latest version of the library with following commands:

Create a wheel package and install using following commands
poetry shell
poetry build - this will create a whl package in dist folder.
pip install <whl file name>. In this case it is applications_security_amber_trustauthority_client_for_python-0.1.0-py3-none-any.whl
 
## Usage

If User has interface to get the quote/evidence and want to attest it with Intel Trust Authority:

Create a new Intel Trust Authority client, then use the exposed services to
access different parts of the Intel Trust Authority API.

### Create Connector instance.
```Python
#Create a config object that contains all parameters to connect to Intel Trust Authority and retry if there is 5XX error.
# base_url: Intel Trust Authority base url
# retry_cfg: Instance of RetryConfig class. Where retry_config has:
# api_url: Intel Trust Authority api url
# api_key: Intel Trust Authority api key

config_obj = config.Config(
            config.RetryConfig(
                int(retry_wait_time_min), int(retry_wait_time_max), int(retry_max)
            ),
            trustauthority_base_url,
            trustAuthority_api_url,
            trust_authority_api_key,
        )
    except ValueError as exc:
        log.error(
            "Either retry_wait_time_min or retry_wait_time_max or retry_max is not a valud integer"
        )
        exit(1)

    if config_obj == None:
        log.error("Error in config() instance initialization")
        exit(1)

#object to the connector
ita_connector = connector.ITAConnector(config_obj)
```

### To get a Intel Trust Authority signed token with Nonce

- Create Adapter
    - **TDX**
        - [Intel TDX](./inteltrustauthorityclient/src/tdx/intel/README.md)
        - [Azure TDX](./inteltrustauthorityclient/src/tdx/azure/README.md)
        - [GCP TDX](./inteltrustauthorityclient/src/tdx/gcp/README.md)
    - **SGX**
        - [Intel SGX](./inteltrustauthorityclient/src/sgx/intel/README.md)


Use the adapter created with following piece of code to get attestation token:

```Python
attest_args = connector.AttestArgs(
            **adapter**, trust_authority_request_id, policy_ids
        )
attestation_token = ita_connector.attest(attest_args)
    if attestation_token is None:
        log.error("Attestation Token is not returned.")
        exit(1)
```

### To verify Intel Trust Authority signed token
```
try:
    verified_token = connector.verify_token(token)
except Exception as exc:
    log.error(f"Token verification returned exception : {exc}")
```

### To download token signing certificates from Intel Trust Authority
```
certs_data = connector.get_token_signing_certificates()
if certs_data == None:
    log.error(
        "getting Token signing certificates from Intel Trust Authority failed"
    )
```

### For E2E token collection and signature verification logic refer
SGX: [SGX Sample App](./inteltrustauthorityclient/examples/sgx_sample_app/README.md)
TDX: [TDX Sample App](./inteltrustauthorityclient/examples/tdx_sample_app/README.md)


### Follow below link to run unit tests
[Unit_Test.md](./docs/build_ut_tests.md) 

## License

This library is distributed under the BSD-style license found in the [LICENSE](./LICENSE)
file.
