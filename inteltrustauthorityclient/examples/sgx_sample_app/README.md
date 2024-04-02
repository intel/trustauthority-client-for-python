# SGX Attestation Sample App
The Intel SGX attestation sample app is a Python application that uses the Intel Trust Authority Attestation Python Client packages
to get an attestation token from Intel Trust Authority. The application contains an example SGX enclave. When run, 
it collects quote from the enclave and sends it to Intel Trust Authority to retrieve a token.

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
│    │    │applications_security_amber |    |    |                |    Authority   |
|    |    | _trustauthority_client_    |    |    |                |                |
|    |    |  for_python-0.1.0-py3-none |    |    |                |                |
|    |    |  -any.whl                  |    |    |                |                |
|    │    |                            │    │    │                |                │
│    │    └────────────────────────────┘    │    │                │   SERVER       │
│    │                                      │    │                └────────────────┘
│    │                                      │    │
│    └──────────────────────────────────────┘    │
│                                                │
│                  SGX Host                      │
└────────────────────────────────────────────────┘
```
The diagram above depicts the components used in the Intel SGX attestation sample app while running within
a Docker container. The Intel SGX sample app can also be run directly on an Intel SGX host, provided that dependencies such as Intel SGX DCAP have been installed. 


## Usage for running TDX Attestation Sample App as a docker container

The [SGX Attestation Sample App](/inteltrustauthorityclient/examples/sgx_sample_app/sgx_sample_app.py) can be encapsulated as a container, enabling it to be executed in containerized environments.

### Prerequisites

Kindly adhere to the outlined steps below for installing both <b>Docker</b> and <b>docker-compose</b>—essential tools for running these applications within Docker containers.

Use <b>Docker version 20.10.17 or a more recent release</b>. Refer to the guide at https://docs.docker.com/engine/install/ubuntu/ for detailed instructions on Docker installation.

Use <b>docker-compose version 1.29.2 or a more recent release</b>. Follow the steps outlined at https://docs.docker.com/compose/install/linux/#install-the-plugin-manually for installing docker-compose.


### Build Instructions

Once `Docker` and `docker-compose` are installed, build the docker image with the following command:

```sh
docker-compose --env-file ../.env build
```

### Deployment Instructions

Once the image is built using the above `docker-compose build` command,
the `SGX Attestation Sample App` can be run using the following commands:

```sh
# Creating tdx_token.env file
cat <<EOF | tee sgx_token.env
ENV_HTTP_PROXY=<http-proxy-host>
ENV_HTTPS_PROXY=<https-proxy-host>
ENV_TRUSTAUTHORITY_BASE_URL=<trustauthority-base-url>
ENV_TRUSTAUTHORITY_API_URL=<trustauthority-api-url>
ENV_TRUSTAUTHORITY_API_KEY=<trustauthority-api-key>
ENV_TRUSTAUTHORITY_REQUEST_ID=<trustauthority-request-id>
ENV_TRUSTAUTHORITY_POLICY_ID=<trustauthority-policy-id>
ENV_RETRY_MAX=<max-number-of-retries>
ENV_RETRY_WAIT_TIME_MAX=<max-retry-wait-time>
ENV_RETRY_WAIT_TIME_MIN=<min-retry-wait-time>
LOG_LEVEL=<log-level>
EOF

# Make sure the Intel(R) SGX driver device is set with the following permissions:
# crw-rw---- root <user-group> /dev/tdx_guest

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
> - The proxy setting values for `ENV_HTTP_PROXY` and `ENV_HTTPS_PROXY` have to be set by the user based on the system proxy settings.
> - The example above uses one such proxy settings and this can vary from system to system.

### Output when example is run...
- When successful, the token and other information will be displayed...


## Usage for running TDX Attestation Sample App as a native application

### Get the package containing `connector` and `tdx` with the following command:

```sh
cd ../../ && \
poetry build
```

### Compile the Sample App with the following command:

```sh
install the wheel file generated and run tdx_sample_app.py
```

### Run the Sample App with the following command:

Please ensure to set these variables in the environment as a pre-requisite:

```sh
export ENV_HTTP_PROXY=<HTTPS_PROXY_HOST>
export ENV_HTTPS_PROXY=<HTTPS_PROXY_HOST>
export ENV_TRUSTAUTHORITY_BASE_URL=<TRUSTAUTHORITY_BASE_URL>
export ENV_TRUSTAUTHORITY_API_URL=<TRUSTAUTHORITY_API_URL>
export ENV_TRUSTAUTHORITY_API_KEY=<TRUSTAUTHORITY_API_KEY>
export ENV_TRUSTAUTHORITY_REQUEST_ID=<TRUSTAUTHORITY_REQUEST_ID>
export ENV_TRUSTAUTHORITY_POLICY_ID=<TRUSTAUTHORITY_POLICY_ID>
export ENV_RETRY_MAX=<MAX_NUMBER_OF_RETRIES>
export ENV_RETRY_WAIT_TIME_MAX=<MAX_RETRY_WAIT_TIME>
ENV_RETRY_WAIT_TIME_MIN=<MAX_RETRY_WAIT_TIME>
export LOG_LEVEL=<LOG_LEVEL>
```

Run the Sample App after setting the environment variables with the following command:

```sh
python sgx_sample_app.py
```

> **Note:**
>
> - The proxy setting values for `ENV_HTTP_PROXY` and `ENV_HTTPS_PROXY` have to be set by the user based on the system proxy settings.
> - The example above uses one such proxy settings and this can vary from system to system.

### Output when example is run...
- When successful, the token and other information will be displayed...
