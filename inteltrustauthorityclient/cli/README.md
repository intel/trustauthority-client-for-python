---
last_updated: 10 July 2024
---

# Intel® Trust Authority CLI for Intel TDX and NVDIA GPU  

Intel® Trust Authority Python CLI for Intel® Trust Domain Extensions (Intel® TDX) and NVIDIA GPU [**trustauthority-pycli**](./cli) provides a CLI 
to attest an Intel TDX trust domain (TD) and NVIDIA GPU with Intel Trust Authority. **trustauthority-pycli** requires **python-connector**, **python-intel-tdx**, **python-nvgpu**, 
and Intel® Software Guard Extensions Data Center Attestation Primitives (Intel® SGX DCAP) and NVIDIA Attestation SDK. 

## Prerequisites
- Intel® SGX DCAP

- Intel TDX Attestation Primitives in TDVM

- NVIDIA Attestation SDK in TDVM

## Intel Trust Authority Configuration
The Trust Authority Python CLI requires a Intel Trust Authority configuration file (config.json) to be provided for the CLI operations. Here is an example configuration:
Save the configuration to 'config.json' file.

```
{
    "trustauthority_base_url": "https://portal.trustauthority.intel.com"
    "trustauthority_api_url": "https://api.trustauthority.intel.com",
    "trustauthority_api_key": "<trustauthority attestation api key>"
}
```

The Trust Authority CLI provides several commands for different operations. Here are the available commands:

## Usage
### evidence
To collect evidence from the Trust Authority.

```sh
python3 trustauthority_pycli.py evidence -a <attest_type> [-n <nonce>] [-u <user_data>]
```
Options:
```
-a, --attest-type: Specify the attestation type (tdx or nvgpu).
-n, --nonce: Optional nonce in base64 encoded format.
-u, --user-data: Optional user data in base64 encoded format.
```

## attest
To request attestation from the Trust Authority.
```sh
python3 trustauthority_pycli.py attest -a <attest_type> -c <config_file> [-u <user_data>] [-p <policy_ids>] [-s <token_sign_alg> [--policy-must-match]
```
Options:
```
-a, --attest-type: Specify the attestation type (tdx, nvgpu, or tdx+nvgpu).
-c, --config: Configuration file path (config.json).
-u, --user-data: Optional user data in base64 encoded format.
-p, --policy-ids: Optional list of Trust Authority policy IDs (comma separated).
-s, --token-sign-alg: Optional token signing algorithm ("RS256" or "PS384")
--policy-must-match: Optional for enforcing policy match during attestation (defaul=False if unused)
```

## verify 
To verify an attestation token.
```sh
python3 trustauthority_pycli.py verify -c <config_file> -t <token in JWT format>
```
Options:
```
-c, --config: Configuration file path.
-t, --token: Attesation Token in JWT format.
```

## License

This source is distributed under the BSD-style license found in the [LICENSE](LICENSE)
file.

