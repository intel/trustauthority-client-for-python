# Intel® Trust Authority Client for Python 

<p style="font-size: 0.875em;">· 02/13/2025 ·</p>

The Intel® Trust Authority Client for Python is a library of Python modules used to perform remote attestation of a Trusted Execution Environment (TEE) using Intel Trust Authority as the verifier. The client packages enable you to collect evidence from the TEE, request an attestation token (JWT), and verify the cryptographic signature of the token.

The Python client currently supports the following TEEs:

- Intel® Software Guard Extensions (Intel® SGX).
- Intel® Trust Domain Extensions (Intel® TDX) for on-premises Intel TDX platforms.
- Google Cloud Platform\* (GCP) confidential VMs with Intel TDX.
- Azure\* confidential VMs with Intel TDX.
- NVIDIA\* H100 GPU and Intel TDX Trust Domain.

## Library structure

- [/inteltrustauthorityclient/connector](inteltrustauthorityclient/connector#readme): Contains the main ITAConnector class to connect to Intel Trust Authority. 
- [/inteltrustauthorityclient/nvgpu](inteltrustauthorityclient/nvgpu#readme): Contains the NVIDIA H100 GPU adapter. 
- [/inteltrustauthorityclient/cli](inteltrustauthorityclient/cli#readme): Contains the Intel Trust Authority Python CLI. This version of the CLI includes support for NVIDIA H100 GPU attestation. This feature is in limited preview status. 
- [/inteltrustauthorityclient/examples](inteltrustauthorityclient/examples): Contains sample applications to demonstrate the usage of the client. See [Sample applications](#sample-applications) for more information.
- [inteltrustauthorityclient/sgx/intel](inteltrustauthorityclient/sgx/intel/README.md): Contains the Intel SGX adapter.
- [inteltrustauthorityclient/tdx](inteltrustauthorityclient/tdx): Contains the Intel TDX bare metal and Google Cloud Platform (GCP) adapter (one adapter supports both platforms), and Azure TDX adapters. 
- [test](test/README.md): Contains unit tests for the client.


## System requirement

- Python 3.8 or newer.
- Ubuntu 22.04 with *kernel 6.7 or later,* or Ubuntu 24.04. Support for the ConfigFS-TSM subsystem is required for Intel TDX attestation.

## Installation

The following installation steps assume that you are installing the Intel Trust Authority Client for Python on an Intel TDX TD, running on an Intel TDX-enabled host server. For information about how to prepare the Intel TDX host server, see [Setup Remote Attestation on Host OS and Inside TD](https://github.com/canonical/tdx?tab=readme-ov-file#8-setup-remote-attestation-on-host-os-and-inside-td) in the [Canonical/TDX](https://github.com/canonical/tdx) repo on GitHub.

To install the latest version of the Intel TDX + NVIDIA H100 client on a TD:

1. Clone the repository, which automatically checks out the main branch.

```bash
git clone https://github.com/intel/trustauthority-client-for-python.git
```

Run the following commands from the `inteltrustauthorityclient` directory.

2. Install **poetry** by running the following command:
    ```sh
    pip3 install --no-cache-dir poetry
    ```
1. Create a wheel package using poetry:

    Spawn a poetry shell:
    ```bash
    poetry shell
    ```
    Build wheel package:
    ```bash
    poetry build
    ```
1. Run pip install <whl file name> to install the **inteltrustauthorityclient** package in site-packages:
    ```bash
    cd ../dist
    pip install applications_security_amber_trustauthority_client_for_python-1.1.0-py3-none-any.whl
    ```

>[!NOTE]
> When you install the client, you might see the following error: "ERROR: pip's dependency resolver does not currently take into account all the packages that are installed." That is followed by a list of version mismatch messages. You can safely ignore this error. The client uses newer versions of the Python libraries than the NVIDIA SDK.


## Usage

More information about how to use this library is available in the READMEs for each package. [Library structure](#library-structure), above, has links to the READMEs for each package.

The primary documentation is the [Python Connector Reference](https://docs.trustauthority.intel.com/main/articles/integrate-python-client.html) in the Intel Trust Authority documentation. 


### Sample applications

For more information on how to use the client, see the sample applications in the [examples](./inteltrustauthorityclient/examples) folder. 

- [Intel SGX sample app](./inteltrustauthorityclient/examples/sgx_sample_app/README.md)
- [Intel TDX sample app](./inteltrustauthorityclient/examples/tdx_sample_app/README.md) — Works on Intel TDX hosts/VMs and Azure TDX VMs.

- Create Adapter using:
    - **TDX**
        - [TDX](./inteltrustauthorityclient/tdx/README.md)
        - [Azure TDX](./inteltrustauthorityclient/tdx/azure/README.md)
    - **SGX**
        - [Intel SGX](./inteltrustauthorityclient/sgx/intel/README.md)
    - **NVIDIA**
        - [NVGPU](./inteltrustauthorityclient/nvgpu/README.md)
### Unit Tests

For more information on how to run the unit tests, see the [Unit Tests README](./test/README.md).

## Code of Conduct and Contributing

See the [Contributing](./CONTRIBUTING.md) file for more information on how to contribute to this project. This project follows the [Code of Conduct](./CODE_OF_CONDUCT.md).
## License

This library is distributed under the BSD-style license found in the [LICENSE](./LICENSE)
file.

<br><br>
---

**\*** Other names and brands may be claimed as the property of others.



