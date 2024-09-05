# TDX Attestation Sample App
The TDX Attestation Sample App is a Python application that uses the Intel Trust Authority Attestation Python Client packages
to fetch token from Intel Trust Authority. The application is supposed to be run inside a TD. When run,
it collects a quote from the TD and sends it to Intel Trust Authority to retrieve a token and verify the same.

```

┌────────────────────────────────────────────────┐
│    ┌──────────────────────────────────────┐    │
│    │          Docker Container            │    │
│    │                                      │    │
│    │    ┌──────────────────────────┐      │    │
│    │    │TDX Attestation Sample App│      │    │                ┌────────────────┐
│    │    └──────────────────────────┘      │    │                │                │
│    │                                      │    │                │                │
|    │    ┌────────────────────────────┐    │◄───┼───────────────►│   INTEL TRUST  │
│    │    │applications_security_amber |    |    |                |    AUTHORITY   |
|    |    | _trustauthority_client_    |    |    |                |     SERVER     |
|    |    |  for_python-1.0.0-py3-none |    |    |                |                |
|    |    |  -any.whl                  |    |    |                |                |
|    │    |                            │    │    │                |                │
│    │    └────────────────────────────┘    │    │                │                │
│    │                                      │    │                └────────────────┘
│    │                                      |    |
│    │                                      |    |
│    │                                      │    │
│    │                                      │    │
│    └──────────────────────────────────────┘    │
│                                                │
│                  TDX Host                      │
└────────────────────────────────────────────────┘
```
The diagram above depicts the components used in the TDX Attestation Sample App while running within
a docker container. The TDX Attestation Sample App example can also be run directly inside a TD vm (provided
the appropriate dependencies like DCAP have been installed).


## Usage for running TDX Attestation Sample App as a docker container

The [TDX Attestation Sample App](../tdx_sample_app/tdx_sample_app.py) can be encapsulated as a container, enabling it to be executed in containerized environments.

### Prerequisites

- Kindly adhere to the outlined steps below for installing both <b>Docker</b> and <b>docker compose</b>—essential tools for running these applications within Docker containers.

  - Use <b>Docker version 20.10.17 or a more recent release</b>. Refer to the guide at https://docs.docker.com/engine/install/ubuntu/ for detailed instructions on Docker installation.

  - Use <b>docker compose version 1.29.2 or a more recent release</b>. Follow the steps outlined at https://docs.docker.com/compose/install/linux/#install-the-plugin-manually for installing docker compose.

- A pre-production TDX host with the TDX kernel and TD installed.
- The TDX host must be able to generate quotes.
- A running instance of Intel Trust Authority 


### Build Instructions

Once `Docker` and `docker compose` are installed, build the Sample Application Docker image in **/inteltrustauthorityclient/examples/tdx_sample_app/** with the following command:

```sh
cat <<EOF | tee .env
UBUNTU_VERSION=20.04
TRUST_AUTHORITY_CLIENT_VERSION=<Sample app Docker Image version>
ADAPTER_TYPE=<Adapter_type> ("tdx"/"aztdx")
EOF

docker compose --env-file .env build
```
**change Adapter_type based on TD being used. Adapter_Type can be one of tdx, aztdx**


### Deployment Instructions

The docker image must be present inside the TD vm.  For example, it can be exported/copied 
from a build machine as follows...
```sh
#Save the tdx sample app Docker image into trust_authority_python_client_tdx_sample_app.tar.gz
docker save trust_authority_python_client_tdx_sample_app:v1.0.0 > trust_authority_python_client_tdx_sample_app.tar.gz
#scp trust_authority_python_client_tdx_sample_app.tar.gz to the TD VM.
#On the TD VM load/import trust_authority_python_client_tdx_sample_app.tar.gz docker image using below command
docker load -i trust_authority_python_client_tdx_sample_app.tar.gz
``` 

### Running the Sample Application

Once the image is built using the above `docker compose` command or loaded from the tar file,
the `TDX Attestation Sample App` image can be run using the following commands:

```sh
# Creating tdx_token.env file
cat <<EOF | tee tdx_token.env
HTTP_PROXY=<http-proxy-host>
HTTPS_PROXY=<https-proxy-host>
TRUSTAUTHORITY_BASE_URL=<trustauthority-base-url>
TRUSTAUTHORITY_API_URL=<trustauthority-api-url>
TRUSTAUTHORITY_API_KEY=<trustauthority-api-key>
TRUSTAUTHORITY_REQUEST_ID=<trustauthority-request-id>
TRUSTAUTHORITY_POLICY_ID=<trustauthority-policy-id> example: ["policy 1","policy 2"]
RETRY_MAX=<max-number-of-retries>
RETRY_WAIT_TIME_MAX=<max-retry-wait-time>
RETRY_WAIT_TIME_MIN=<min-retry-wait-time>
CLIENT_TIMEOUT_SEC=<request-timeout-sec>
LOG_LEVEL=<log-level>
POLICY_MUST_MATCH=True/False
TOKEN_SIGNING_ALGORITHM=<Algorithm>
EOF

# Use docker to run the TDX Sample App...
For Azure TDX:
sudo docker run \
-it --rm --device=/dev/tpm0 \
--device=/dev/tpmrm0 \
--env-file tdx_token.env \
--group-add $(getent group tss | cut -d: -f3) \
trust_authority_python_client_tdx_sample_app:v1.0.0


For For Google Cloud / Intel® Developer Cloud TDX adapters:
docker run \
       --rm \
       --privileged \
       --network host \
       -v /sys/kernel/config:/sys/kernel/config \
       --env-file tdx_token.env \
       trust_authority_python_client_tdx_sample_app:v1.0.0     
```

> **Note:**
>
> - The proxy setting values for `HTTP_PROXY` and `HTTPS_PROXY` have to be set by the user based on the system proxy settings.
> - The example above uses one such proxy settings and this can vary from system to system.
> - Token Signing Algorithm should be either PS384 or RS256.

### Output when example is run...
- When successful, the token and other information will be displayed...


## Usage for running TDX Attestation Sample App as a native application

#### Build the Python wheel package containing connector and adapter packages from **/applications.security.amber.trustauthority-client-for-python** folder containing poetry configuration files using the following command:

```sh
cd /inteltrustauthorityclient && \
poetry shell && \
poetry build
```

### Compile the Sample App with the following command:

- Go to  dist folder where a whl package is created.
```Python
pip install <whl file name>
```
- In this case it is `applications_security_amber_trustauthority_client_for_python-1.0.0-py3-none-any.whl` inteltrustauthorityclient package is installed in site-packages:


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
export POLICY_MUST_MATCH=True/False
export TOKEN_SIGNING_ALGORITHM=<Algorithm>
```


Run the Sample App in **/inteltrustauthorityclient/examples/tdx_sample_app/** after setting the environment variables using the following command:

```sh
python tdx_sample_app.py
```

> **Note:**
>
> - The proxy setting values for `HTTP_PROXY` and `HTTPS_PROXY` have to be set by the user based on the system proxy settings.
> - The example above uses one such proxy settings and this can vary from system to system.
> - Token Signing Algorithm should be either PS384 or RS256.

### Output when example is run...
- When successful, the token and other information will be displayed...
