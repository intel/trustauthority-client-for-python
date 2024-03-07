"""
Copyright (c) 2024 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""

import base64
import json
import uuid
import jwt
import os
import http
import requests
import validators
import logging as log
from tenacity import Retrying, stop_after_attempt, retry_if_exception_type
from datetime import *
from cryptography.exceptions import InvalidSignature
from urllib.parse import urljoin
from uuid import UUID
from typing import List, Optional
from dataclasses import dataclass
from cryptography import x509
from cryptography.x509 import load_der_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from src.base.evidence_adapter import EvidenceAdapter

from src.connector.evidence import Evidence
from src.resources import constants as constants
from src.tdx.intel.tdx_adapter import TDXAdapter


@dataclass
class GetNonceArgs:
    """GetNonceArgs holds the request parameters needed for getting nonce from Intel Trust Authority"""

    request_id: str


@dataclass
class GetNonceResponse:
    """GetNonceResponse holds the response parameters received from nonce endpoint"""

    headers: str
    nonce: str


@dataclass
class VerifierNonce:
    """VerifierNonce holds signed nonce issued from Intel Trust Authority"""

    val: str
    iat: str
    signature: str


@dataclass
class AttestArgs:
    """AttestArgs holds the request parameters needed for attestation with Intel Trust Authority"""

    adapter: EvidenceAdapter
    request_id: Optional[str] = None
    policy_ids: Optional[List[UUID]] = None


@dataclass
class AttestResponse:
    """AttestResponse holds the response parameters recieved during attestation flow"""

    token: str
    headers: str


@dataclass
class GetTokenArgs:
    """GetTokenArgs holds the request parameters needed for getting token from Intel Trust Authority"""

    nonce: VerifierNonce
    evidence: Evidence
    policy_ids: List[UUID]
    request_id: str


@dataclass
class GetTokenResponse:
    """GetTokenResponse holds the response parameters recieved from attest endpoint"""

    token: str
    headers: str


@dataclass
class TDXTokenRequest:
    """TokenRequest holds all the data required for TDX attestation"""

    quote: str  #'json:"quote"'
    verifier_nonce: VerifierNonce  #'json:"verifier_nonce"'
    user_data: str  #'json:"runtime_data"'
    runtime_data: str  #'json:"runtime_data"'
    policy_ids: Optional[List[UUID]] = None  #'json:"policy_ids"'
    event_log: Optional[str] = None  #'json:"event_log"'
    def __post_init__(self):
        if self.event_log is None:
            delattr(self, "event_log")
        if self.user_data is None:
            delattr(self, "user_data")

class ITAConnector:
    """
    Initializes Intel Trust Authority connector object that is used to connect to Intel Trust Authority to get nonce,
    get attestation token, get CRL and verify CRL and verify Attestation token
    """

    def __init__(self, cfg) -> None:
        """Initializes Intel Trust Authority connector object and exposes functionalities for getting nonce,
           getting Attestation Token, get CRL, verify CRL and verify Attestation Token

        Args:
            config(): config object containing connection attributes of Intel Trust Authority
        """
        self.cfg = cfg

    def get_nonce(self, args: GetNonceArgs) -> GetNonceResponse:
        """This Function calls Intel Trust Authority rest api to get nonce.

        Args:
            GetNonceArgs(): Instance of GetNonceArgs class

        Returns:
            GetNonceResponse: object to GetNonceResponse class
        """
        retry_call = Retrying(
            stop=stop_after_attempt(self.cfg.retry_cfg.retry_max_num),
            wait=self.cfg.retry_cfg.backoff,
            retry=retry_if_exception_type(requests.exceptions.HTTPError),
            reraise=True,
        )

        def make_request():
            url = urljoin(self.cfg.api_url, constants.NONCE_URL)
            log.info(f"get_nonce() http request url: {url}")
            headers = {
                "x-api-key": self.cfg.api_key,
                "Accept": "application/json",
                "request-id": args.request_id,
            }
            http_proxy = os.getenv(constants.HTTP_PROXY)
            https_proxy = os.getenv(constants.HTTPS_PROXY)
            proxies = {"http": http_proxy, "https": https_proxy}
            try:
                response = requests.get(
                    url,
                    headers=headers,
                    proxies=proxies,
                )
                response.raise_for_status()
            except requests.exceptions.HTTPError as exc:
                log.error(f"Http Error occurred in get_nonce request: {exc}")
                if self.cfg.retry_cfg.check_retry(response.status_code):
                    raise exc
                else:
                    log.error("Since error is not retryable hence not retrying")
                    return None
            except requests.exceptions.ConnectionError as exc:
                log.error(f"Connection Error occurred in get_nonce request: {exc}")
                return None
            except requests.exceptions.Timeout as exc:
                log.error(f"Timeout Error occurred in get_nonce request: {exc}")
                return None
            except requests.exceptions.RequestException as exc:
                log.error(f"Error occurred in get_nonce request: {exc}")
                return None
            except Exception as exc:
                log.error(f"Error occurred in get_token request: {exc}")
                return None
            return response

        try:
            response = retry_call.__call__(make_request)
        except requests.exceptions.HTTPError:
            return None
        except Exception as exc:
            log.error(f"Error occurred in get_token request: {exc}")
            return None
        if response is None:
            return None

        nonce_data = response.json()
        nonce = VerifierNonce(
            nonce_data.get("val"),
            nonce_data.get("iat"),
            nonce_data.get("signature"),
        )
        return GetNonceResponse(response.headers, nonce)

    def get_token(self, args: GetTokenArgs) -> GetTokenResponse:
        """This Function calls Intel Trust Authority rest api to get Attestation Token.

        Args:
            GetTokenArgs(): Instance of GetTokenArgs class

        Returns:
            GetTokenResponse: object to GetTokenResponse class
        """
        if args.policy_ids != None:
            for uuid_str in args.policy_ids:
                if not validate_uuid(uuid_str):
                    log.error(f"Invalid policy UUID :{uuid_str}")
                    return None
        retry_call = Retrying(
            stop=stop_after_attempt(self.cfg.retry_cfg.retry_max_num),
            wait=self.cfg.retry_cfg.backoff,
            retry=retry_if_exception_type(requests.exceptions.HTTPError),
            reraise=True,
        )

        def make_request():
            headers = {
                "x-Api-Key": self.cfg.api_key,
                "Accept": "application/json",
                "Content-Type": "application/json",
                "Request-Id": args.request_id,
            }
            if args.evidence.adapter_type == constants.AZURE_TDX_ADAPTER:
                url = urljoin(self.cfg.api_url, constants.AZURE_TDX_ATTEST_URL)
                token_req = TDXTokenRequest(
                    quote=args.evidence.quote,
                    verifier_nonce=VerifierNonce(
                        args.nonce.val, args.nonce.iat, args.nonce.signature
                    ).__dict__,
                    user_data=base64.b64encode(args.evidence.user_data.encode()).decode(
                        "utf-8"
                    ),
                    runtime_data=None if args.evidence.runtime_data is None else base64.b64encode(args.evidence.runtime_data).decode("utf-8"),
                    policy_ids=args.policy_ids,
                )
            elif args.evidence.adapter_type == constants.INTEL_TDX_ADAPTER:
                url = urljoin(self.cfg.api_url, constants.INTEL_TDX_ATTEST_URL)
                encoded_quote = base64.b64encode(args.evidence.quote).decode("utf-8")
                token_req = TDXTokenRequest(
                    quote=encoded_quote,
                    verifier_nonce=VerifierNonce(
                        args.nonce.val, args.nonce.iat, args.nonce.signature
                    ).__dict__,
                    user_data=None,
                    runtime_data=base64.b64encode(args.evidence.user_data.encode()).decode(
                        "utf-8"
                    ),
                    policy_ids=args.policy_ids,
                    event_log=args.evidence.event_log,
                )
            else:
                log.error("Invalid Adapter type")
                exit(1)
            body = token_req.__dict__
            http_proxy = os.getenv(constants.HTTP_PROXY)
            https_proxy = os.getenv(constants.HTTPS_PROXY)
            proxies = {"http": http_proxy, "https": https_proxy}
            log.info(
                f"making attestation token request to Intel Trust Authority ... : {url}"
            )
            try:
                response = requests.post(
                    url,
                    headers=headers,
                    data=json.dumps(body),
                    proxies=proxies,
                )
                response.raise_for_status()
            except requests.exceptions.HTTPError as exc:
                log.error(f"Http Error occurred in get_token request: {exc}")
                if self.cfg.retry_cfg.check_retry(response.status_code):
                    raise exc
                else:
                    log.error("Since error is not retryable hence not retrying")
                    return None
            except requests.exceptions.ConnectionError as exc:
                log.error(f"Connection Error occurred in get_token request: {exc}")
                return None
            except requests.exceptions.Timeout as exc:
                log.error(f"Timeout Error occurred in get_token request: {exc}")
                return None
            except requests.exceptions.RequestException as exc:
                log.error(f"Error occurred in get_token request: {exc}")
                return None
            except Exception as exc:
                log.error(f"Error occurred in get_token request: {exc}")
                return None
            return response

        try:
            response = retry_call.__call__(make_request)
        except requests.exceptions.HTTPError:
            return None
        except Exception as exc:
            log.error(f"Error occurred in get_token request: {exc}")
            return None

        if response is None:
            return None
        return GetTokenResponse(response.json().get("token"), str(response.headers))

    def get_crl(self, crl_url):
        """This Function makes get request to CRL Distribution point and return CRL Object.

        Args:
            crl_arr: list of crl distribution points

        Returns:
            Certificate Authority CRL object
        """
        retry_call = Retrying(
            stop=stop_after_attempt(self.cfg.retry_cfg.retry_max_num),
            wait=self.cfg.retry_cfg.backoff,
            retry=retry_if_exception_type(requests.exceptions.HTTPError),
            reraise=True,
        )

        if crl_url == "":
            log.error("CRL URL missing in the certificate")
            return None
        if validators.url(crl_url):
            http_proxy = os.getenv(constants.HTTP_PROXY)
            https_proxy = os.getenv(constants.HTTPS_PROXY)
            proxies = {"http": http_proxy, "https": https_proxy}

            def make_request():
                try:
                    response = requests.get(crl_url, proxies=proxies)
                    response.raise_for_status()
                except requests.exceptions.HTTPError as exc:
                    log.error(f"Http Error occurred in get_crl request: {exc}")
                    if self.cfg.retry_cfg.check_retry(response.status_code):
                        raise exc
                    else:
                        log.error("Since error is not retryable hence not retrying")
                        return None
                except requests.exceptions.ConnectionError as exc:
                    log.error(f"Connection Error occurred in get_crl request: {exc}")
                except requests.exceptions.Timeout as exc:
                    log.error(f"Timeout Error occurred in get_crl request: {exc}")
                    return None
                except requests.exceptions.RequestException as exc:
                    log.error(f"Error occurred in get_crl request: {exc}")
                    return None
                crl_obj = x509.load_der_x509_crl(response.content, default_backend())
                return crl_obj

            try:
                response = retry_call.__call__(make_request)
            except requests.exceptions.RequestException as exc:
                return None
            except Exception as exc:
                log.error(f"Error occurred in get_token request: {exc}")
                return None

            if response is None:
                return None
            return response

    def verify_crl(self, crl, leaf_cert, ca_cert):
        """This Function verify certificate against crl object

        Args:
            crl: crl object
            leaf_cert: leaf certificate
            ca_cert: ca certificate
        """
        if leaf_cert is None or ca_cert is None or crl is None:
            log.error("Leaf Cert, CA Cert, or CRL is None")
            return False
        pub_key = ca_cert.public_key()
        if not (crl.is_signature_valid(pub_key)):
            log.error("Invalid CRL signature")
            return False
        dt = datetime.now(timezone.utc)
        utc_time = dt.replace(tzinfo=timezone.utc)
        utc_timestamp = utc_time.timestamp()
        if crl.next_update_utc.timestamp() < utc_timestamp:
            log.error("crl has been expired")
            return False
        if (
            crl.get_revoked_certificate_by_serial_number(leaf_cert.serial_number)
            != None
        ):
            log.error("certificate has been revoked")
            return False
        return True

    def verify_token(self, token):
        """This Function verify Attestation token issued by Intel Trust Authority

        Args:
            token: Intel Trust Authority Attestation Token
        """
        unverified_headers = jwt.get_unverified_header(token)
        kid = unverified_headers.get("kid", None)
        if kid is None:
            log.error("Missing key id in token")
            return None
        log.debug(f"kid : {kid}")

        # Get the JWT Signing Certificates from Intel Trust Authority
        jwks_data = self.get_token_signing_certificates()
        if jwks_data == None:
            log.error(
                "getting Token signing certificates from Intel Trust Authority failed"
            )
            return None
        keyid_exists = False
        for key in jwks_data.get("keys", []):
            if key.get("kid") == kid:
                keyid_exists = True
                log.debug("key found: %s", key.get("kid"))
                x5c_certificates = key.get("x5c", [])
                break
        if not (keyid_exists):
            log.error("Could not find Key matching the key id")
            return None
        if len(x5c_certificates) > constants.ATS_CERTCHAIN_MAXLENGTH:
            log.error(
                "Token Signing Cert chain has more than %d certificates",
                constants.AtsCertChainMaxLen,
            )
            return None

        # Get Root, Intermediate and Leaf certificates from x5c Token signing certificates list
        root = []
        intermediate = []
        leaf_cert = None
        inter_ca_cert = None
        root_cert = None
        for cert in x5c_certificates:
            cert_data = load_der_x509_certificate(base64.b64decode(cert))
            if (
                cert_data.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                == cert_data.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                and cert_data.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[
                    0
                ].value.find("Root CA")
                != -1
            ):
                root.append(cert_data)
                root_cert = cert_data
            elif (
                cert_data.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                != cert_data.issuer.get_attributes_for_oid(x509.NameOID.COMMON_NAME)
                and cert_data.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[
                    0
                ].value.find("Signing CA")
                != -1
            ):
                intermediate.append(cert_data)
                inter_ca_cert = cert_data
            else:
                leaf_cert = cert_data

        # Validate Intermediate CA Certificate against Root CA CRL
        cdp_list = inter_ca_cert.extensions.get_extension_for_oid(
            x509.ExtensionOID.CRL_DISTRIBUTION_POINTS
        )
        inter_ca_crl_url = cdp_list.value[0].full_name[0].value
        log.debug(f"inter ca crl url : {inter_ca_crl_url}")
        root_crl_obj = self.get_crl(inter_ca_crl_url)
        if root_crl_obj == None:
            log.error("Failed to get ROOT CA CRL Object")
            return None
        if not self.verify_crl(root_crl_obj, inter_ca_cert, root_cert):
            log.error("Failed to check Intermediate CA Certificate against Root CA CRL")
            return None

        # Validate Leaf certificate against Intermediate CA CRL
        cdp_list = leaf_cert.extensions.get_extension_for_oid(
            x509.ExtensionOID.CRL_DISTRIBUTION_POINTS
        )
        leaf_crl_url = cdp_list.value[0].full_name[0].value
        log.debug(f"leaf crl url : {leaf_crl_url}")
        intermediate_ca_crl_obj = self.get_crl(leaf_crl_url)
        if intermediate_ca_crl_obj == None:
            log.error("Failed to get INTERMEDIATE CA CRL Object")
            return None
        if not self.verify_crl(intermediate_ca_crl_obj, leaf_cert, inter_ca_cert):
            log.error("Failed to check Leaf Certificate against Intermediate CA CRL")
            return None

        # verifying the leaf certificate with both the intermediate CA certificate and the root certificate
        try:
            root_cert.public_key().verify(
                inter_ca_cert.signature,
                inter_ca_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                inter_ca_cert.signature_hash_algorithm,
            )
        except InvalidSignature as exc:
            log.error(
                f"Error in verifying inter ca certificate against root certificate : {exc}"
            )
            return None
        try:
            inter_ca_cert.public_key().verify(
                leaf_cert.signature,
                leaf_cert.tbs_certificate_bytes,
                padding.PKCS1v15(),
                leaf_cert.signature_hash_algorithm,
            )
        except InvalidSignature as exc:
            log.error(
                f"Error in verifying leaf certificate against inter ca certificate : {exc}"
            )
            return None
        log.debug(
            "Leaf certificate verification against Root and Inter ca certificate Successful"
        )

        try:
            # Decode the JWT Attestation Token using leaf certificate public key and algorithm used to encode the token
            decoded_token = jwt.decode(token, leaf_cert.public_key(), unverified_headers.get("alg"))
        except jwt.ExpiredSignatureError:
            log.error("Attestation Token has expired.")
            return None
        except jwt.InvalidTokenError:
            log.error("Invalid Attestation token.")
            return None
        except Exception as exc:
            log.error(f"Caught Exception in Attestation Token Verification: {exc}")
            return None
        else:
            log.debug("Attestation Token Verification Successful")
            return decoded_token

    def get_token_signing_certificates(self):
        """This Function retrieve token signing certificates from Intel Trust Authority"""

        retry_call = Retrying(
            stop=stop_after_attempt(self.cfg.retry_cfg.retry_max_num),
            wait=self.cfg.retry_cfg.backoff,
            retry=retry_if_exception_type(requests.exceptions.HTTPError),
            reraise=True,
        )

        def make_request():
            url = urljoin(self.cfg.base_url, "certs")
            http_proxy = os.getenv(constants.HTTP_PROXY)
            https_proxy = os.getenv(constants.HTTPS_PROXY)
            proxies = {"http": http_proxy, "https": https_proxy}
            headers = {
                "Accept": "application/json",
            }
            log.debug(f"Making request to get_token_signing_certificates() url : {url}")
            try:
                response = requests.get(
                    url,
                    headers=headers,
                    proxies=proxies,
                )

                response.raise_for_status()
            except requests.exceptions.HTTPError as exc:
                log.error(
                    f"Http Error occurred in get_token_signing_certificates request: {exc}"
                )
                if self.cfg.retry_cfg.check_retry(response.status_code):
                    raise exc
                else:
                    log.error("Since error is not retryable hence not retrying")
                    return None
            except requests.exceptions.ConnectionError as exc:
                log.error(
                    f"Connection Error occurred in get_token_signing_certificates request: {exc}"
                )
                return None
            except requests.exceptions.Timeout as exc:
                log.error(
                    f"Timeout Error occurred in get_token_signing_certificates request: {exc}"
                )
                return None
            except requests.exceptions.RequestException as exc:
                log.error(
                    f"Error occurred in get_token_signing_certificates request: {exc}"
                )
                return None
            return response

        try:
            response = retry_call.__call__(make_request)
        except requests.exceptions.RequestException as exc:
            return None
        except Exception as exc:
            log.error(f"Error occurred in get_token request: {exc}")
            return None

        if response is None:
            return None

        jwks = response.json()
        return jwks

    def attest(self, args: AttestArgs) -> AttestResponse:
        """This Function calls Intel Trust Authority Connector endpoints get_nonce(), collect evidence from adapter
           class, get_token() and return the attestation token.

        Args:
            AttestArgs: Instance of AttestArgs class

        Returns:
            AttestResponse: Instance of AttestResponse class
        """
        if args.policy_ids != None:
            for uuid_str in args.policy_ids:
                if not validate_uuid(uuid_str):
                    log.error(f"Invalid policy UUID :{uuid_str}")
                    return None
        response = AttestResponse
        nonce_resp = self.get_nonce(GetNonceArgs(args.request_id))
        if nonce_resp == None:
            log.error("Get Nonce request failed")
            return None
        log.info("Nonce Retrieved Successfully")
        log.debug(f"Nonce : {nonce_resp.nonce}")
        decoded_val = base64.b64decode(nonce_resp.nonce.val)
        decoded_iat = base64.b64decode(nonce_resp.nonce.iat)
        concatenated_nonce = decoded_val + decoded_iat
        evidence = args.adapter.collect_evidence(concatenated_nonce)
        if evidence == None:
            return None
        token_resp = self.get_token(
            GetTokenArgs(nonce_resp.nonce, evidence, args.policy_ids, args.request_id)
        )
        if token_resp == None:
            log.debug("Get Token request failed")
            return None
        response.token = token_resp.token
        response.headers = token_resp.headers
        return response


def validate_uuid(uuid_str):
    try:
        uuid.UUID(uuid_str)
        return True
    except ValueError as exc:
        log.error(f"ValueError occurred in UUID check request: {exc}")
        return False
    except TypeError as exc:
        log.error(f"TypeError occurred in UUID check request: {exc}")
        return False
