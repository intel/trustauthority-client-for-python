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
ARG ADAPTER_TYPE
ENV ADAPTER_TYPE=${ADAPTER_TYPE}

RUN apt-get update && apt-get install -y --no-install-recommends build-essential python3 pip

RUN if [ "${ADAPTER_TYPE}" = "aztdx" ]; then \
        apt-get install -y --no-install-recommends tpm2-tools; \
    fi

COPY --from=build_base /app/dist/applications_security_amber_trustauthority_client_for_python-1.0.0-py3-none-any.whl .
RUN pip install applications_security_amber_trustauthority_client_for_python-1.0.0-py3-none-any.whl
    
# Set the working directory inside the container
WORKDIR /app
COPY . .
WORKDIR /app/inteltrustauthorityclient/examples/tdx_sample_app
CMD ["python3", "tdx_sample_app.py"]
