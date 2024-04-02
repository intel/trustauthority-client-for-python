# Copyright (C) 2023 Intel Corporation
# SPDX-License-Identifier: BSD-3-Clause

ARG VERSION=v0.0.0
ARG COMMIT=fffffff
ARG DCAP_VERSION=0.0
ARG PSW_VERSION=0.0

FROM ubuntu:20.04 AS build
ARG DEBIAN_FRONTEND=noninteractive
ARG ENABLE_DEBUG
ARG DCAP_VERSION
ARG PSW_VERSION
ARG PSW_VERSION=${PSW_VERSION}
ARG ADAPTER_TYPE
ENV ADAPTER_TYPE=${ADAPTER_TYPE}

RUN apt-get update; \
    apt-get upgrade -y; \
    apt-get autoremove -y; \
    apt-get install -y --no-install-recommends gnupg wget make curl git python pip ca-certificates

#Adding sgx repo to ubuntu focals
RUN echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' > /etc/apt/sources.list.d/intel-sgx.list
RUN curl https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key -o /tmp/intel-sgx-deb.key; \
    apt-key add /tmp/intel-sgx-deb.key; \
    rm /tmp/intel-sgx-deb.key

RUN apt-get update
RUN apt-get update -y && apt-get install -y --no-install-recommends build-essential

WORKDIR /opt/intel
#download sgx sdk binary
RUN wget -q https://download.01.org/intel-sgx/sgx-linux/2.22/distro/ubuntu20.04-server/sgx_linux_x64_sdk_${PSW_VERSION}.bin; \
    chmod +x sgx_linux_x64_sdk_${PSW_VERSION}.bin; \
    echo 'yes' | ./sgx_linux_x64_sdk_${PSW_VERSION}.bin

#Installing linux SGX sdk
RUN apt-get update && apt-get install -y --no-install-recommends \
    libsgx-urts=${PSW_VERSION}-focal1 \
    libsgx-qe3-logic=${DCAP_VERSION} \
    libsgx-pce-logic=${DCAP_VERSION} \
    libsgx-dcap-ql=${DCAP_VERSION} \
    libsgx-dcap-ql-dev=${DCAP_VERSION} \
    libcurl4-openssl-dev \
    libsgx-dcap-default-qpl=${DCAP_VERSION} \
    libsgx-quote-ex=${PSW_VERSION}-focal1

WORKDIR /app

COPY pyproject.toml poetry.lock ./
ENV PYTHONPATH=/app

RUN pip3 install --no-cache-dir poetry
RUN poetry install --no-dev --no-interaction --no-ansi
COPY . .
WORKDIR /app/inteltrustauthorityclient/examples/sgx_sample_app/minimal-enclave
RUN make clean all
ENV LD_LIBRARY_PATH=/app/inteltrustauthorityclient/examples/sgx_sample_app/minimal-enclave:/usr/local/lib/:/usr/lib/
WORKDIR /app/inteltrustauthorityclient/examples/sgx_sample_app
ENTRYPOINT ["poetry", "run", "python3", "sgx_sample_app.py"]