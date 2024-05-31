# SGX Attestation Sample App
The Intel SGX attestation sample app is a Python application that uses the Intel Trust Authority Attestation Python Client packages
to fetch attestation token from Intel Trust Authority. The Sample Application contains an example SGX enclave. When run, 
it collects quote from the enclave and sends it to Intel Trust Authority to retrieve a token that can be verified.

```
┌────────────────────────────────────────────────┐
│    ┌──────────────────────────────────────┐    │
│    │          Docker Container            │    │
│    │                                      │    │
│    │    ┌──────────────────────────┐      │    │
│    │    │SGX Attestation Sample App│      │    │                
│    │    └──────────────────────────┘      │    │                                
│    │                                      │    │                                
│    │    ┌──────────────────────────┐      │    |
│    │    │     enclave.signed.so    │      │    │                
│    │    └──────────────────────────┘      │    │                ┌────────────────┐
|    |                                      |    |                |                |
|    |                                      |    |                |                |
|    │    ┌────────────────────────────┐    │◄───┼───────────────►│   INTEL TRUST  │
│    │    │applications_security_amber |    |    |                |    AUTHORITY   |
|    |    | _trustauthority_client_    |    |    |                |     SERVER     |
|    |    |  for_python-1.0.0-py3-none |    |    |                |                |
|    |    |  -any.whl                  |    |    |                |                |
|    │    |                            │    │    │                |                │
│    │    └────────────────────────────┘    │    │                │                │
│    │                                      │    │                └────────────────┘
│    │                                      │    │
│    └──────────────────────────────────────┘    │
│                                                │
│                  SGX Host                      │
└────────────────────────────────────────────────┘
```
The diagram above depicts the components used in the SGX attestation sample app while running within
a Docker container. The Intel SGX sample app can also be run directly on an Intel SGX host, provided that dependencies such as Intel SGX DCAP have been installed. 


## Usage for running SGX Attestation Sample App as a docker container

The [SGX Attestation Sample App](../sgx_sample_app/sgx_sample_app.py) can be encapsulated as a container, enabling it to be executed in containerized environments.

### Prerequisites

- Kindly adhere to the outlined steps below for installing both <b>Docker</b> and <b>docker-compose</b>—essential tools for running this application within Docker container.

    - Use <b>Docker version 20.10.17 or a more recent release</b>. Refer to the guide at https://docs.docker.com/engine/install/ubuntu/ for detailed instructions on Docker installation.
    - Use <b>docker-compose version 1.29.2 or a more recent release</b>. Follow the steps outlined at https://docs.docker.com/compose/install/linux/#install-the-plugin-manually for installing docker-compose.
- A production SGX host with the SGX driver Installed and can generate quotes.
- A running instance of Intel Trust Authority.



### Build Instructions

Once `docker` and `docker-compose` are installed, build the Sample Application Docker image in **/inteltrustauthorityclient/examples/sgx_sample_app/** with the following command:

```sh
cat <<EOF | tee .env
UBUNTU_VERSION=20.04
TRUST_AUTHORITY_CLIENT_VERSION=<Sample app Docker Image version>
DCAP_VERSION=<sgx sdk dcap version>
PSW_VERSION=<sgx sdk psw version>
ADAPTER_TYPE=INTEL-SGX
EOF

docker-compose --env-file .env build
```

### Deployment Instructions

The docker image must be present inside the TD vm.  For example, it can be exported/copied 
from a build machine as follows...
```sh
#Save the sgx sample app Docker image into trust_authority_python_client_sgx_sample_app.tar.gz
docker save trust_authority_python_client_sgx_sample_app:v1.0.0 > trust_authority_python_client_sgx_sample_app.tar.gz
#scp trust_authority_python_client_sgx_sample_app.tar.gz to the TD VM.
#On the TD VM load/import trust_authority_python_client_sgx_sample_app.tar.gz docker image using below command
docker load -i trust_authority_python_client_sgx_sample_app.tar.gz
``` 

### Running the Sample Application

Once the image is built using the above `docker-compose build` command or loaded from the tar file,
the `SGX Attestation Sample App` can be run using the following commands:

```sh
# Creating sgx_token.env file
cat <<EOF | tee sgx_token.env
HTTP_PROXY=<http-proxy-host>
HTTPS_PROXY=<https-proxy-host>
TRUSTAUTHORITY_BASE_URL=<trustauthority-base-url>
TRUSTAUTHORITY_API_URL=<trustauthority-api-url>
TRUSTAUTHORITY_API_KEY=<trustauthority-api-key>
TRUSTAUTHORITY_REQUEST_ID=<trustauthority-request-id>
TRUSTAUTHORITY_POLICY_ID=<trustauthority-policy-id>
RETRY_MAX=<max-number-of-retries>
RETRY_WAIT_TIME_MAX=<max-retry-wait-time>
RETRY_WAIT_TIME_MIN=<min-retry-wait-time>
CLIENT_TIMEOUT_SEC=<request-timeout-sec>
LOG_LEVEL=<log-level>
SGX_AESM_ADDR=1
TRUSTAUTHORITY_POLICY_MUST_MATCH=<bool>
TRUSTAUTHORITY_TOKEN_SIGNING_ALGORITHM=<Algorithm>
EOF

# Use docker to run the SGX Sample App...
sudo docker run \
        --rm \
        -it \
        --device=/dev/sgx_enclave \
        --device=/dev/sgx_provision \
        -v /var/run/aesmd/aesm.socket:/var/run/aesmd/aesm.socket  \
        --env-file sgx_token.env \
        --group-add $(getent group sgx_prv | cut -d: -f3) \
        trust_authority_python_client_sgx_sample_app:v1.0.0

```

> **Note:**
>
> - The proxy setting values for `HTTP_PROXY` and `HTTPS_PROXY` have to be set by the user based on the system proxy settings.
> - The example above uses one such proxy settings and this can vary from system to system.
> - Token Signing Algorithm should be one of PS384 or RS256.

### Output when example is run...
- When successful, the token and other information will be displayed...


## Usage for running SGX Attestation Sample App as a native application

### Build the Python wheel package containing connector and adapter packages from **/applications.security.amber.trustauthority-client-for-python** folder containing poetry configuration files using the following command:

```sh
cd ../../.. && \
poetry shell && \
poetry build
```

### Compile the Sample App with the following command:

- Goto  dist folder where a whl package is created.
- pip install < whl file name>. In this case it is applications_security_amber_trustauthority_client_for_python-1.0.0-py3-none-any.whl. inteltrustauthorityclient package is installed in site-packages:
```
pip install <whl file name>
```

### Run the Sample App with the following command:

Please ensure to set these variables in the environment as a pre-requisite:

```sh
export HTTP_PROXY=<HTTPS_PROXY_HOST>
export HTTPS_PROXY=<HTTPS_PROXY_HOST>
export TRUSTAUTHORITY_BASE_URL=<TRUSTAUTHORITY_BASE_URL>
export TRUSTAUTHORITY_API_URL=<TRUSTAUTHORITY_API_URL>
export TRUSTAUTHORITY_API_KEY=<TRUSTAUTHORITY_API_KEY>
export TRUSTAUTHORITY_REQUEST_ID=<TRUSTAUTHORITY_REQUEST_ID>
export TRUSTAUTHORITY_POLICY_ID=<TRUSTAUTHORITY_POLICY_ID>
export RETRY_MAX=<MAX_NUMBER_OF_RETRIES>
export RETRY_WAIT_TIME_MAX=<MAX_RETRY_WAIT_TIME>
export RETRY_WAIT_TIME_MIN=<MAX_RETRY_WAIT_TIME>
export CLIENT_TIMEOUT_SEC=<REQUEST_TIMEOUT_SEC>
export LOG_LEVEL=<LOG_LEVEL>
export SGX_AESM_ADDR=1
export ADAPTER_TYPE="INTEL-SGX"
export TRUSTAUTHORITY_POLICY_MUST_MATCH=<bool>
export TRUSTAUTHORITY_TOKEN_SIGNING_ALGORITHM=<Algorithm>
```

Run the Sample App in **/inteltrustauthorityclient/examples/sgx_sample_app/** after setting the environment variables using the following command:

```sh
python sgx_sample_app.py
```

> **Note:**
> - The proxy setting values for `HTTP_PROXY` and `HTTPS_PROXY` have to be set by the user based on the system proxy settings.
> - The example above uses one such proxy settings and this can vary from system to system.
> - Token Signing Algorithm should be one of PS384 or RS256.

### Output when example is run...
- When successful, the token and other information will be displayed...
