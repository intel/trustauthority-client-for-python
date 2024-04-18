###########################################
# Copyright (c) 2023-2024 Intel Corporation
# All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
###########################################

ARG UBUNTU_VERSION
FROM ubuntu:$UBUNTU_VERSION

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive \
    TZ=UTC \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Add intel USER
ARG USERNAME=intel
ARG USER_UID=1001
ARG USER_GID=$USER_UID

RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME

# Install system dependencies
RUN  apt-get update; \
    apt-get upgrade -y; \
    apt-get autoremove -y; \
  apt-get install -y --no-install-recommends gnupg wget make curl git python3 python3-pip

#Adding sgx repo to ubuntu focals
ARG DCAP_VERSION
ARG ADAPTER_TYPE
ENV ADAPTER_TYPE=${ADAPTER_TYPE}
RUN echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' > /etc/apt/sources.list.d/intel-sgx.list
RUN curl https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key -o /tmp/intel-sgx-deb.key; \
    apt-key add /tmp/intel-sgx-deb.key; \
    rm /tmp/intel-sgx-deb.key

RUN apt-get update && apt-get install -y --no-install-recommends build-essential

#Installing linux TDX sdk
RUN if [ "${ADAPTER_TYPE}" = "INTEL-TDX" ]; then \
        apt-get install -y --no-install-recommends libtdx-attest-dev=${DCAP_VERSION} libtdx-attest=${DCAP_VERSION}; \
    fi

RUN if [ "${ADAPTER_TYPE}" = "AZURE-TDX" ]; then \
        apt-get install -y --no-install-recommends tpm2-tools; \
    fi

# Install Poetry
RUN pip3 install --no-cache-dir poetry

# Set the working directory inside the container
WORKDIR /app

# Copy only the dependency files to avoid invalidating cache unnecessarily
COPY pyproject.toml poetry.lock ./

ENV PYTHONPATH=/app

# Install project dependencies
RUN poetry install --no-dev --no-interaction --no-ansi

# Copy the rest of the project files
COPY . .
WORKDIR /app/inteltrustauthorityclient/examples/tdx_sample_app
#TODO: Check why this is not working.
#USER $USERNAME
# Specify the command to run your application
CMD ["poetry", "run", "python3", "tdx_sample_app.py"]