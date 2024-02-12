# TDX Attestation Sample App
The TDX Attestation Sample App is a Python application that uses the Intel Trust Authority Attestation Python Client package
to fetch token from Intel Trust Authority. The application is supposed to be run inside a TD. When run,
it collects a quote from the TD and sends it to Intel Trust Authority to retrieve a token and verifies the token.

## Running TDX Attestation Sample App Using Docker
Navigate to /examples/tdx_sample_app/
### Build Docker Image
```
docker compose --env-file ../.env build
```
### Run Sample App Container
```
docker run --rm --network host --device=/dev/tdx_guest --env-file ./config.env --group-add $(getent group root | cut -d: -f3) trust_authority_python_client_tdx_sample_app:v1.0.0
```