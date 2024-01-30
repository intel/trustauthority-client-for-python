###########################################
# Copyright (c) 2023-2024 Intel Corporation
# All rights reserved.
# SPDX-License-Identifier: BSD-3-Clause
###########################################

ARG UBUNTU_VERSION
FROM ubuntu:$UBUNTU_VERSION
ENV DEBIAN_FRONTEND=noninteractive

# Add intel USER
ARG USERNAME=intel
ARG USER_UID=1001
ARG USER_GID=$USER_UID

RUN groupadd --gid $USER_GID $USERNAME \
    && useradd --uid $USER_UID --gid $USER_GID -m $USERNAME

RUN apt-get update; \
    apt-get upgrade -y; \
    apt-get autoremove -y; \
  apt-get install -y --no-install-recommends gnupg wget make curl git python3 python3-pip

#Adding sgx repo to ubuntu focals
ARG DCAP_VERSION
RUN echo 'deb [arch=amd64] https://download.01.org/intel-sgx/sgx_repo/ubuntu focal main' > /etc/apt/sources.list.d/intel-sgx.list
RUN curl https://download.01.org/intel-sgx/sgx_repo/ubuntu/intel-sgx-deb.key -o /tmp/intel-sgx-deb.key; \
    apt-key add /tmp/intel-sgx-deb.key; \
    rm /tmp/intel-sgx-deb.key

#Installing linux TDX sdk
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        libtdx-attest-dev=${DCAP_VERSION} \
        libtdx-attest=${DCAP_VERSION}

WORKDIR /trustauthority-client-python
COPY . .

WORKDIR /trustauthority-client-python/examples/tdx_sample_app
RUN pip3 install poetry platformdirs && \
    poetry config virtualenvs.create false && \
    poetry install

ENV PYTHONPATH=/trustauthority-client-python
# Set USER to intel
USER $USERNAME
CMD ["poetry", "run", "python3", "tdx_sample_app.py"]
