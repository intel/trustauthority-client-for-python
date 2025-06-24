
# IIntel® Tiber™ Trust Authority CLI for Intel TDX and NVIDIA H100 GPU  

<p style="font-size: 0.875em;">· 05/21/2025 ·</p>

Intel® Tiber™ Trust Authority Python CLI ("CLI") for Intel® Trust Domain Extensions (Intel® TDX) and NVIDIA\* H100\* GPU [**trustauthority-pycli**](../cli) provides a CLI to attest an Intel TDX trust domain (TD) and a NVIDIA H100 GPU with Intel Trust Authority. 

This version of the CLI works with Intel® Trust Domain Extensions (Intel® TDX) and NVIDIA H100 Confidential Computing enabled platforms. 

For more information, see [GPU Remote Attestation](https://docs.trustauthority.intel.com/main/articles/articles/ita/concept-gpu-attestation.html) in the Intel Trust Authority documentation.

## Prerequisites

The following prerequisites must be installed on the CVM (Confidential VM with Intel TDX):

- Use **Python 3.8 or newer**.
- Ubuntu 22.04 with *kernel 6.7 or later,* or Ubuntu 24.04. Support for the ConfigFS-TSM subsystem is required for Intel TDX attestation.
- NVIDIA H100 GPU
- [NVIDIA Attestation SDK v1.4.0](https://github.com/NVIDIA/nvtrust/releases/tag/v1.4.0) installed in the guest TD. NVIDIA Attestation SDK v2.x is _not_ supported. 

> [!NOTE]
> The NVIDIA Attestation SDK requires the GPU Local Verifier. The version must match the SDK v1.4

## Intel Trust Authority Configuration

The CLI requires a configuration file (config.json) to be provided for the CLI operations. The following is an example of the configuration file:

```
{
    "trustauthority_base_url": "https://portal.trustauthority.intel.com"
    "trustauthority_api_url": "https://api.trustauthority.intel.com",
    "trustauthority_api_key": "<trustauthority attestation api key>"
}
```
> [!NOTE]
 > If you are in the European Union (EU) region, use the following Intel Trust Authority URLs:<br> Base URL — https://portal.eu.trustauthority.intel.com <br> API URL — https://api.eu.trustauthority.intel.com

Save the configuration to a 'config.json' file. The `attest` command requires the configuration file path as an argument, and allows you to specify a path to the file so that it doesn't need to be in the same directory as the CLI binary.

## Installation

Refer to the main [README](../../README.md#installation) for installation instructions. 

For convenience, you may want to define an alias to run the CLI by running the following commands. You must replace **\<path_to_pythonclient\>** with the path to the directory where you'll install the client (e.g., pythonclient).

```bash
# Create an alias for the Trust Authority CLI (inteltrustauthorityclient/cli)
export CLIPATH=<path_to_pythonclient>/inteltrustauthorityclient/cli/trustauthority-pycli;
alias trustauthority-pycli="sudo python3 $CLIPATH/trustauthority-cli.py" 
```
Sudo is optional in the alias defined above, but it's required to run the CLI commands that collect evidence from the TEE and it's convenient to have it in the alias.

You can check to see that the CLI is installed correctly by running the following command.

```bash
# Print the help message
trustauthority-pycli -h
```
If you didn't define an alias, use the following commands. 

```bash
cd <path_to_pythonclient>/inteltrustauthorityclient/cli/trustauthority-pycli
python3 trustauthority_cli.py -h
```

## Usage

**Sudo** or root is required to run the `evidence` and `attest` commands. That's because root permission is needed to access **config/tsm** to collect evidence for an Intel TDX quote. The `verify` command doesn't require root privileges.

The following examples assume that you've defined a `trustauthority_pycli` alias.

### `evidence`

Collects evidence for attestation from an Intel TDX trust domain or a NVIDIA H100 GPU (one at a time; evidence doesn't support both in a single call). This command collects evidence but doesn't send it to Intel Trust Authority for attestation. If successful, `evidence` prints the GPU evidence or Intel TDX quote to the screen (of course, output can also be piped to a file). This command can be used in Background-check attestation flow or in development and testing. 

```sh
trustauthority_pycli evidence -a <attest_type> [-n <nonce>] [-u <user_data>]
```
Options:
```
-a, --attest-type: Specify the TEE type, valid values are "tdx" or "nvgpu".
-n, --nonce: Optional nonce in base64-encoded format.
-u, --user-data: Optional user data in base64-encoded format.
```

### `attest`

Collects evidence from the TEE or GPU and sends it to Intel Trust Authority for attestation. `attest` returns an attestation token in JWT format if the attestation is successful. This command can attest an Intel TDX trust domain, a NVIDIA H100 GPU, or both. `attest` uses values set in the `config.json` file to locate the Trust Authority REST API gateway and authenticate requests.

```sh
trustauthority_pycli attest -a <attest_type> -c <config_file> [-u <user_data>] [-p <policy_ids>] [-s <token_sign_alg> [--policy-must-match]
```
Options:
```
-a, --attest-type: Specify the TEE type to attest; valid values are "tdx", "nvgpu", or "tdx+nvgpu".
-c, --config: Configuration file path (config.json).
-u, --user-data: Optional user data in base64-encoded format.
-p, --policy-ids: An optional list of Trust Authority policy IDs (comma separated). 
-s, --token-sign-alg: Optional token signing algorithm ("RS256" or "PS384"). The default is "PS384".
--policy-must-match: Optional boolean for enforcing policy match during attestation. If set to "True", a token is issued only if all attestation policies match. If set to "False", a token is issued even if one or all policies are unmatched. The default is "False".
```

### `verify` 

Verifies an attestation token to ensure that the token is generated from a genuine Intel Trust Authority service. This command verifies the token signature and format, but it doesn't verify claims. If the token is valid, the command prints the token claims to the screen.

```sh
trustauthority_pycli verify -c <config_file> -t <token in JWT format>
```
Options:
```
-c, --config: Configuration file path.
-t, --token: An Intel Trust Authority attestation token in JWT format.
```

## License

This source is distributed under the BSD-style license found in the [LICENSE](../../LICENSE)
file.

<br><br>
---

**\*** Other names and brands may be claimed as the property of others.
