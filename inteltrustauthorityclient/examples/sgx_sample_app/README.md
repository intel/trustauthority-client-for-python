# Intel SGX Attestation Sample Application

<p style="font-size: 0.875em;">· 05/21/2025 ·</p> 

The Intel® Software Guard Extensions (Intel® SGX) attestation sample app is a Python application that uses the Intel® Tiber™ Trust Authority Client for Python packages to attest an Intel SGX enclave. The attestation verifier is [Intel® Trust Authority](https://trustauthority.intel.com). 

The sample application runs in a minimal Intel SGX enclave. When the sample app is run, it does the following:

1. Evokes the Python client and TEE adapter to collect a quote from the host
1. Calls the Intel Trust Authority REST API to request an attestation token, using the quote obtained in step 1. 
1. If attestation is successful, the sample app prints the JWT and other information to the terminal. A real application would most likely use the attestation token to authenticate with a service or to authorize access to a resource. This is known as the _passport_ attestation model.

The following retro, ASCII-like diagram depicts the components used in the Intel SGX attestation sample app running within a Docker container that is itself running on an Intel SGX host. 

```
┌────────────────────────────────────────────────┐
│    ┌──────────────────────────────────────┐    │
│    │          Docker Container            │    │
│    │                                      │    │
│    │    ┌──────────────────────────┐      │    │
│    │    │Intel SGX attestation app │      │    │                
│    │    └──────────────────────────┘      │    │                                
│    │                                      │    │                                
│    │    ┌──────────────────────────┐      │    |
│    │    │     enclave.signed.so    │      │    │                
│    │    └──────────────────────────┘      │    │                ┌────────────────┐
|    |                                      |    |                |                |
|    |                                      |    |                |                |
|    │    ┌────────────────────────────┐    │◄───┼───────────────►│   INTEL TRUST  │
│    │    │applications_security_amber |    |    |                |    AUTHORITY   |
|    |    | _trustauthority_client_    |    |    |                |     SERVICE    |
|    |    |  for_python-1.1.0-py3-none |    |    |                |                |
|    |    |  -any.whl                  |    |    |                |                |
|    │    |                            │    │    │                |                │
│    │    └────────────────────────────┘    │    │                │                │
│    │                                      │    │                └────────────────┘
│    │                                      │    │
│    └──────────────────────────────────────┘    │
│                                                │
│                  Intel SGX Host                │
└────────────────────────────────────────────────┘
```


## How to build and run the application

The sample app can be run as a [Docker container](#run-the-application-in-a-docker-container) or as a [native application on an Intel SGX host](#run-the-sample-application-from-an-intel-sgx-host). In either case, you must set certain runtime variables before running the sample app.

### Runtime variables

The Python client and REST API require configuration before use. The following runtime variables correspond to client configuration, API endpoints, and authorization settings in the client API. For the Docker container, you will set these variables in the `sgx_token.env` file. For the native application, you'll export a set of variables in the shell environment. The following table describes the runtime variables and their purpose.

Many of these variables are optional but several are required as indicated.

| Variable | Type | Required? | Description |
| :--- | :--- | :--- | :--- |
| `HTTP_PROXY` | String | No | HTTP proxy host. [1] |
| `HTTPS_PROXY` | String | No | HTTPS proxy host. [1]|
| `TRUSTAUTHORITY_BASE_URL` | String | Yes | Base URL for the Intel Trust Authority service. [2]|
| `TRUSTAUTHORITY_API_URL` | String | Yes | API URL for the Intel Trust Authority service. [2] |
| `TRUSTAUTHORITY_API_KEY` | String | Yes | Attestation API key required for authorization. [3] For more information, see [User roles and API keys](https://docs.trustauthority.intel.com/main/articles/articles/ita/concept-user-roles-and-api-keys.html) in the Intel Trust Authority Documentation.  |
| `TRUSTAUTHORITY_REQUEST_ID` | String | No | If not provided, a request ID will be created by the API gateway. An auto-generated request ID is not guaranteed to be unique.|
| `TRUSTAUTHORITY_POLICY_ID` | String | No | If supplied, the value can be a single policy ID (UUID) or a list of policy IDs separated by commas. For more information, see [Attestation Policies](https://docs.trustauthority.intel.com/main/articles/articles/ita/concept-policy-v2.html) in the Intel Trust Authority documentation.|
| `RETRY_MAX` | Integer | No | Maximum number of retries. |
| `RETRY_WAIT_TIME_MAX` | Integer | No | Maximum retry wait time. |
| `RETRY_WAIT_TIME_MIN` | Integer | No | Minimum retry wait time. |
| `CLIENT_TIMEOUT_SEC` | Integer | No | Request timeout in seconds. |
| `LOG_LEVEL` | String | No | Log level. |
| `ADAPTER_TYPE` | String | Yes | Specifies which adapter to collect evidence for a quote. For this example, the only allowable value is "sgx". |
| `POLICY_MUST_MATCH` | Boolean | No | If set to `true`, the policy (or policies, if more than one) specified by TRUSTAUTHORITY_POLICY_ID or the API key must all match for an attestation token to be issued. If not supplied or set to `false`, the default behavior is to issue an attestation token even if one or more policies fail to match. |
| `TOKEN_SIGNING_ALGORITHM` | String | No | It specifies the algorithm to be used for signing the token. If supplied, it must be one of **PS384** or **RS256**. Defaults to PS384. |

**Notes**<br>
**[1]** The `HTTP_PROXY` and `HTTPS_PROXY` variables are optional. If your system is behind a proxy, set these variables to the proxy host. If you are not behind a proxy, you can leave these variables unset. <br>
**[2]** The `TRUSTAUTHORITY_BASE_URL` and `TRUSTAUTHORITY_API_URL` URLs are determined by the region associated with your subscription. If you're using the **US** region, the URLS are `https://portal.trustauthority.intel.com` and `https://api.trustauthority.intel.com` respectively. If you're using the **EU** region, the URLs are `https://portal.eu.trustauthority.intel.com` and `https://api.eu.trustauthority.intel.com` respectively.<br>**[3]** The API key must be created in the same region as the URLs above. An API key that was created in one region won't work in the other region.

### Run the application in a Docker container

The Intel SGX attestation sample application can be encapsulated as a container, enabling it to be executed in containerized environments. Begin by copying the Intel Trust Authority Client for Python repository to a local folder. Then build the Docker image, create the `sgx_token.env` file, and run the sample app.

#### Prerequisites

- Use <b>Docker version 20.10.17 or a more recent release</b>. Refer to the guide at https://docs.docker.com/engine/install/ubuntu/ for detailed instructions on Docker installation.
- Use <b>docker-compose version 1.29.2 or a more recent release</b>. Follow the steps outlined at https://docs.docker.com/compose/install/linux/#install-the-plugin-manually for installing docker-compose.
- A Intel SGX host with the Intel SGX driver.
- A subscription to Intel Trust Authority. If you don't have a subscription, you can find out how to get one at [Intel Trust Authority](https://trustauthority.intel.com).

#### Build instructions

1. Build the sample application Docker image in **/inteltrustauthorityclient/examples/sgx_sample_app/** with the following command.

```sh
cat <<EOF | tee .env
UBUNTU_VERSION=20.04
TRUST_AUTHORITY_CLIENT_VERSION=v1.1.0
DCAP_VERSION=1.19.100.3-focal1
PSW_VERSION=2.22.100.3
ADAPTER_TYPE="sgx"
EOF

docker compose --env-file .env build
```
UBUNTU_VERSION — This example has a dependency on Ubuntu 20.04.<br>
TRUST_AUTHORITY_CLIENT_VERSION — The version of the sample app Docker image. This version number is used to tag the Docker image.<br>
DCAP_VERSION — The version of Intel® SGX DCAP installed on the Intel SGX host.<br>
PSW_VERSION — The version of Intel® SGX PSW installed on the Intel SGX host.<br>
ADAPTER_TYPE — "sgx" is the only allowable value for this example.

2. The docker image must be run on the Intel SGX host.  For example, it can be exported or copied 
from a build machine as follows...
```sh
#Save the sgx sample app Docker image into trust_authority_python_client_sgx_sample_app.tar.gz
docker save trust_authority_python_client_sgx_sample_app:v1.1.0 > trust_authority_python_client_sgx_sample_app.tar.gz
#scp trust_authority_python_client_sgx_sample_app.tar.gz to the TD VM.
#On the TD VM load/import trust_authority_python_client_sgx_sample_app.tar.gz docker image using below command
docker load -i trust_authority_python_client_sgx_sample_app.tar.gz
``` 

3. Once the image is built using the above `docker compose` command or loaded from the tar file,
the `SGX Attestation Sample App` can be run using the following commands. Substitute the correct values for the placeholders in the `sgx_token.env` file, and remove the variables that are not required.

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
POLICY_MUST_MATCH=True/False
TOKEN_SIGNING_ALGORITHM=<Algorithm>
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
        trust_authority_python_client_sgx_sample_app:v1.1.0

```

If the sample application runs successfully, the attestation token returned from Intel Trust Authority and other information will be displayed.

### Run the sample application from an Intel SGX host

Begin by copying the Intel Trust Authority Client for Python repository to a local folder where you will build and install the application. Then build and install the Python wheel package containing the connector and adapter packages. Export the required environment variables and run the sample app.

#### Prerequisites

- Python 3.8 or later
- Poetry. You can install **poetry** using the command `pip3 install --no-cache-dir poetry`.
- An Intel SGX host with the Intel SGX driver.
- A subscription to Intel Trust Authority. If you don't have a subscription, you can find out how to get one at [Intel Trust Authority](https://trustauthority.intel.com).

#### Build instructions

1. Build the Python wheel package containing connector and adapter packages from https://github.com/intel/trustauthority-client-for-python folder containing the poetry configuration files using the following command:

```sh
cd ../../.. && \
poetry shell && \
poetry build
```

2. Go to the distribution folder where the whl package was created and install the package using the following command.

```python
pip install applications_security_amber_trustauthority_client_for_python-1.1.0-py3-none-any.whl
```

3. Export environment variables.

The following environment variables can be exported before running the sample app. Most of these variables are optional, but several are required. Substitute the correct values for the placeholders and remove the variables that are not required. See [Runtime variables](#runtime-variables) for details.

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
export ADAPTER_TYPE="sgx"
export POLICY_MUST_MATCH=True/False
export TOKEN_SIGNING_ALGORITHM=<Algorithm>
```

4. Run the Sample App in **/inteltrustauthorityclient/examples/sgx_sample_app/** after setting the environment variables using the following command:

```sh
python sgx_sample_app.py
```

If successful, the token and other information will be displayed.
