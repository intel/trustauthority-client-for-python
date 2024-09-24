###########################################
# Copyright (c) 2023-2024 Intel Corporation
# All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
###########################################

ARG VERSION=v0.0.0
ARG DCAP_VERSION=0.0
ARG PSW_VERSION=0.0

ARG UBUNTU_VERSION
FROM ubuntu:$UBUNTU_VERSION as build_base
ARG DEBIAN_FRONTEND=noninteractive
ARG ENABLE_DEBUG

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get autoremove -y && \
    apt-get install -y --no-install-recommends ca-certificates pip

# Set the working directory inside the container
WORKDIR /app
COPY pyproject.toml poetry.lock ./
# Install poetry
RUN pip3 install --no-cache-dir poetry
COPY . .
RUN poetry build

FROM ubuntu:$UBUNTU_VERSION
ARG DCAP_VERSION
ARG PSW_VERSION
ARG USERNAME=intel
ARG USER_UID=1001
ARG USER_GID=$USER_UID

RUN groupadd --gid $USER_GID $USERNAME && \
    useradd --uid $USER_UID --gid $USER_GID -m $USERNAME
ARG ADAPTER_TYPE
ENV ADAPTER_TYPE=${ADAPTER_TYPE}
RUN apt update && apt install -y --no-install-recommends gnupg wget python3 pip build-essential

# Adding SGX repo to Ubuntu focal
RUN echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' > /etc/apt/sources.list.d/intel-sgx.list && \
    wget https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key -O /tmp/intel-sgx-deb.key && \
    apt-key add /tmp/intel-sgx-deb.key && \
    rm /tmp/intel-sgx-deb.key

WORKDIR /opt/intel
# Download SGX SDK binary
RUN wget -q https://download.01.org/intel-sgx/sgx-linux/2.22/distro/ubuntu20.04-server/sgx_linux_x64_sdk_${PSW_VERSION}.bin && \
    chmod +x sgx_linux_x64_sdk_${PSW_VERSION}.bin && \
    echo 'yes' | ./sgx_linux_x64_sdk_${PSW_VERSION}.bin

# Installing Linux SGX SDK
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsgx-urts=${PSW_VERSION}-focal1 \
    libsgx-qe3-logic=${DCAP_VERSION} \
    libsgx-pce-logic=${DCAP_VERSION} \
    libsgx-dcap-ql=${DCAP_VERSION} \
    libsgx-dcap-ql-dev=${DCAP_VERSION} \
    libcurl4-openssl-dev \
    libsgx-dcap-default-qpl=${DCAP_VERSION} \
    libsgx-quote-ex=${PSW_VERSION}-focal1

COPY --from=build_base /app/dist/applications_security_amber_trustauthority_client_for_python-1.1.0-py3-none-any.whl .
RUN pip install applications_security_amber_trustauthority_client_for_python-1.1.0-py3-none-any.whl
WORKDIR /app
COPY . .

# Change permissions for intel user to run make command in /minimal-enclave
RUN chown -R $USERNAME:$USERNAME /app/inteltrustauthorityclient/examples/sgx_sample_app/minimal-enclave

# Change current user to intel inside the container
USER $USERNAME
WORKDIR /app/inteltrustauthorityclient/examples/sgx_sample_app/minimal-enclave
RUN make clean all

# Set LD_LIBRARY_PATH
ENV LD_LIBRARY_PATH=/app/inteltrustauthorityclient/examples/sgx_sample_app/minimal-enclave:/usr/local/lib/:/usr/lib/

# Set the working directory inside the container
WORKDIR /app/inteltrustauthorityclient/examples/sgx_sample_app
ENTRYPOINT ["python3", "sgx_sample_app.py"]