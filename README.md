# Intel® Trust Authority Client for Python 

<p style="font-size: 0.875em;">· 08/15/2024 ·</p>

The Intel® Trust Authority Client for Python is a library of Python modules used to perform remote attestation of a Trusted Execution Environment (TEE) using Intel Trust Authority as the verifier. The client packages enable you to collect evidence from the TEE, request an attestation token (JWT), and verify the cryptographic signature of the token.

The Intel Trust Authority client is designed for use by both attesting applications and relying parties. It can be used in either Passport or Background-check [attestation patterns](https://docs.trustauthority.intel.com/main/articles/concept-patterns.html?tabs=passport). The client is [available in several languages](https://docs.trustauthority.intel.com/main/articles/integrate-overview.html), including Go, C, and Java. All the clients share a common API.

Both the connector and a TEE adapter (the platform-specific software that collects evidence from a TEE) must be installed on the attesting TEE to collect evidence for attestation. However, a TEE adapter is not required to use the client to verify a token, or to request attestation in background-check mode using a quote provided by the attester. 

The Python client currently supports the following TEEs:

- Intel® Software Guard Extensions (Intel® SGX).
- Intel® Trust Domain Extensions (Intel® TDX) for on-premises Intel TDX platforms.
- Azure\* confidential VMs with Intel TDX.

## Library structure

- [/inteltrustauthorityclient/connector](inteltrustauthorityclient/connector#readme): Contains the main ITAConnector class to connect to Intel Trust Authority. 
- [/inteltrustauthorityclient/examples](inteltrustauthorityclient/examples): Contains sample applications to demonstrate the usage of the client. See [Sample applications](#sample-applications) for more information.
- [inteltrustauthorityclient/sgx/intel](inteltrustauthorityclient/sgx/intel/README.md): Contains the Intel SGX adapter.
- [inteltrustauthorityclient/tdx](inteltrustauthorityclient/tdx): Contains the Intel TDX and Azure TDX adapters. See the READMEs in the subfolders for more information.
- [test](test/README.md): Contains unit tests for the client.


## System requirement

- Ubuntu 22.04 LTS
- Python 3.8 or later

## Installation
 
To install the latest version of the Intel Trust Authority Client for Python library:
 
1. Install **poetry** using the command `pip3 install --no-cache-dir poetry`
1. Create a wheel package using poetry:
    Spawn a poetry shell:
    ```bash
    poetry shell
    ```
    Build wheel package:
    ```bash
    poetry build
    ```
1. Change to the distribution folder where the wheel package was created.
1. Run pip install <whl file name> to install the **inteltrustauthorityclient** package in site-packages:
    ```bash
    pip install applications_security_amber_trustauthority_client_for_python-0.1.0-py3-none-any.whl
    ```
## Usage

More information about how to use this library is available in the READMEs for each package. [Library structure](#library-structure), above, has links to the READMEs for each package.

The primary documentation is the [Python Connector Reference](https://docs.trustauthority.intel.com/main/articles/integrate-python-client.html) in the Intel Trust Authority documentation. 

In general, the Python Connector Reference has more detail and context than the READMES. However, the READMES are updated with every release and may contain updates that haven't been added to the documentation yet. It's a good idea to check both.

### Sample applications

For more information on how to use the client, see the sample applications in the [examples](./inteltrustauthorityclient/examples) folder. 

- [Intel SGX sample app](./inteltrustauthorityclient/examples/sgx_sample_app/README.md)
- [Intel TDX sample app](./inteltrustauthorityclient/examples/tdx_sample_app/README.md) — Works on Intel TDX hosts/VMs and Azure TDX VMs.

### Unit Tests

For more information on how to run the unit tests, see the [Unit Tests README](./test/README.md).

## License

This library is distributed under the BSD-style license found in the [LICENSE](./LICENSE)
file.

<br><br>
---

**\*** Other names and brands may be claimed as the property of others.