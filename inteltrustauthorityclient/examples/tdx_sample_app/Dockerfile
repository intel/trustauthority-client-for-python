###########################################
# Copyright (c) 2023-2024 Intel Corporation
# All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
###########################################

ARG UBUNTU_VERSION
FROM ubuntu:$UBUNTU_VERSION as build_base

RUN apt-get update && \
    apt-get upgrade -y && \
    apt-get autoremove -y && \
    apt-get install -y --no-install-recommends pip

# Set the working directory inside the container
WORKDIR /app
COPY pyproject.toml poetry.lock ./
ENV PYTHONPATH=/app
# Install poetry
RUN pip3 install --no-cache-dir poetry
COPY . .
RUN poetry build

FROM ubuntu:$UBUNTU_VERSION
# Add intel USER
ARG USERNAME=intel
ARG USER_UID=1001
ARG USER_GID=$USER_UID
RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive \
    TZ=UTC \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1
    
# Install system dependencies
RUN  apt-get update; \
    apt-get upgrade -y; \
    apt-get autoremove -y; \
    apt-get install -y --no-install-recommends gnupg curl ca-certificates

#Adding sgx repo to ubuntu focals
ARG DCAP_VERSION
ARG ADAPTER_TYPE
ENV ADAPTER_TYPE=${ADAPTER_TYPE}
RUN echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' > /etc/apt/sources.list.d/intel-sgx.list
RUN curl https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key -o /tmp/intel-sgx-deb.key; \
    apt-key add /tmp/intel-sgx-deb.key; \
    rm /tmp/intel-sgx-deb.key

RUN apt-get update && apt-get install -y --no-install-recommends build-essential python3 pip

#Installing linux TDX sdk
RUN if [ "${ADAPTER_TYPE}" = "INTEL-TDX" ]; then \
        apt-get install -y --no-install-recommends libtdx-attest-dev=${DCAP_VERSION} libtdx-attest=${DCAP_VERSION}; \
    fi

RUN if [ "${ADAPTER_TYPE}" = "AZURE-TDX" ]; then \
        apt-get install -y --no-install-recommends tpm2-tools; \
    fi

COPY --from=build_base /app/dist/applications_security_amber_trustauthority_client_for_python-1.0.0-py3-none-any.whl .
RUN pip install applications_security_amber_trustauthority_client_for_python-1.0.0-py3-none-any.whl
    
# Set the working directory inside the container
WORKDIR /app
COPY . .
WORKDIR /app/inteltrustauthorityclient/examples/tdx_sample_app
CMD ["python3", "tdx_sample_app.py"]