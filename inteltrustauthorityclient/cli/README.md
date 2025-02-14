
# Intel® Trust Authority CLI for Intel TDX and NVIDIA H100 GPU  

<p style="font-size: 0.875em;">· 02/13/2025 ·</p>

Intel® Trust Authority Python CLI ("CLI") for Intel® Trust Domain Extensions (Intel® TDX) and NVIDIA\* H100\* GPU [**trustauthority-pycli**](../cli) provides a CLI 
to attest an Intel TDX trust domain (TD) and a NVIDIA H100 GPU with [Intel Trust Authority](https://www.intel.com/content/www/us/en/security/trust-authority.html). 

This version of the CLI works with on-premises Intel® Trust Domain Extensions (Intel® TDX) and NVIDIA H100 Confidential Computing enabled platforms. A future version may support cloud-based platforms.

For more information, see [GPU Remote Attestation](https://docs.trustauthority.intel.com/main/articles/concept-gpu-attestation.html) in the Intel Trust Authority documentation.

## Prerequisites

Intel Trust Authority Client for Python CLI requirements for the TD are:
- Python 3.8 or newer.
- Ubuntu 22.04 (requires a kernel update) or Ubuntu 24.04. 
- Linux kernel 6.7 or later. Kernel support for the ConfigFS-TSM subsystem is required for Intel TDX attestation and UEFI-based logs.
- Required for the H100 adapter: [NVIDIA Attestation SDK v1.4.0](https://github.com/NVIDIA/nvtrust/releases/tag/v1.4.0). 


## Installation

The Python CLI for Intel TDX is part of the Intel Trust Authority Client for Python. Refer to the main [README](../../README.md#installation) for installation instructions. 

## Intel Trust Authority Configuration

The CLI requires a configuration file (config.json) to be provided for the CLI operations. The following is an example of the configuration file:

```
{
    "trustauthority_base_url": "https://portal.trustauthority.intel.com"
    "trustauthority_api_url": "https://api.trustauthority.intel.com",
    "trustauthority_api_key": "<trustauthority attestation api key>"
}
```
Save the configuration to a 'config.json' file. The `attest` command requires the configuration file path as an argument, and allows you to specify a path to the file so that it doesn't need to be in the same directory as the CLI binary.

> [!NOTE]
 > If you are in the European Union (EU) region, use the following Intel Trust Authority URLs:<br> Base URL — https://portal.eu.trustauthority.intel.com <br> API URL — https://api.eu.trustauthority.intel.com

### Optional steps

You can use the following commands to create an environment variable and alias to run the ClI, for convenience during development and testing. Run the following command after replacing _<path_to_pythonclient>_ with the path to the directory where `inteltrustauthorityclient` is installed:

```
alias trustauthority-pycli="sudo python3 <path_to_pythonclient>/inteltrustauthorityclient/cli/trustauthority-pycli/trustauthority-cli.py" 
```
Sudo is optional in the alias defined above. (`Evidence` and `Attest` require **sudo**;  `Verify` does not.)

Check to see that the CLI is installed by displaying the Help message:

```bash
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
