"""
Copyright (c) 2024 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""

import base64
import json
import jwt
import http
import requests
import logging as log
from datetime import *
from cryptography.exceptions import InvalidSignature
from src.resources import logging as logger
from src.connector.evidence import Evidence
from src.resources import constants as constants
from src.tdx.tdx_adapter import TDXAdapter
from urllib.parse import urljoin
from uuid import UUID
from typing import List, Optional
from dataclasses import dataclass
from cryptography import x509
from cryptography.x509 import load_der_x509_certificate
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding


@dataclass
class GetNonceArgs:
    request_id: str


@dataclass
class GetNonceResponse:
    headers: str
    nonce: str


@dataclass
class VerifierNonce:
    val: str
    iat: str
    signature: str


@dataclass
class AttestArgs:
    adapter: TDXAdapter()
    request_id: str
    policy_ids: Optional[List[UUID]] = None


@dataclass
class AttestResponse:
    token: str
    headers: str


@dataclass
class GetTokenArgs:
    nonce: VerifierNonce
    evidence: Evidence
    policy_ids: List[UUID]
    request_id: str


@dataclass
class GetTokenResponse:
    token: str
    headers: str


@dataclass
class AttestationTokenResponse:
    token: str


@dataclass
class TokenRequest:
    quote: bytearray  #'json:"quote"'
    verifier_nonce: VerifierNonce  #'json:"verifier_nonce"'
    runtime_data: str  #'json:"runtime_data"'
    policy_ids: Optional[List[UUID]] = None  #'json:"policy_ids"'
    event_log: Optional[str] = None  #'json:"event_log"'


class ITAConnector:
    """
    This class creates connector to ITA and provide api endpoints for methods like
    get_nonce(), get_token(), get_token_signing_certificates(), verify_token()
    """

    def __init__(self, cfg) -> None:
        """Initializes ITA connector object and exposes functionalities for getting nonce,
           getting Attestation Token, get CRL, verify CRL, verify Attestation Token and
           Attest.

        Args:
            config(): config object containing connection attributes of ITA
        """
        self.cfg = cfg

    def get_nonce(self, args: GetNonceArgs) -> GetNonceResponse:
        """This Function calls ITA rest api to get nonce.

        Args:
            GetNonceArgs(): Instance of GetNonceArgs class

        Returns:
            GetNonceResponse: object to GetNonceResponse class
        """
        url = urljoin(self.cfg.api_url, "appraisal/v1/nonce")
        log.info("get_nonce() http request url: %s ", url)
        headers = {
            "x-api-key": self.cfg.api_key,
            "Accept": "application/json",
            "request-id": args.request_id,
        }
        http_proxy = constants.HTTP_PROXY
        https_proxy = constants.HTTPS_PROXY
        proxies = {"http": http_proxy, "https": https_proxy}
        response = requests.get(
            url,
            headers=headers,
            proxies=proxies,
            timeout=self.cfg.retry_cfg.retry_wait_time,
        )
        response.raise_for_status()
        nonce_data = response.json()
        nonce = VerifierNonce(
            nonce_data.get("val"),
            nonce_data.get("iat"),
            nonce_data.get("signature"),
        )
        nonce_response = GetNonceResponse(response.headers, nonce)
        return nonce_response

    def get_token(self, args: GetTokenArgs) -> GetTokenResponse:
        """This Function calls ITA rest api to get Attestation Token.

        Args:
            GetTokenArgs(): Instance of GetTokenArgs class

        Returns:
            GetTokenResponse: object to GetTokenResponse class
        """
        url = urljoin(self.cfg.api_url, "appraisal/v1/attest")
        headers = {
            "x-Api-Key": self.cfg.api_key,
            "Accept": "application/json",
            "Content-Type": "application/json",
            "Request-Id": args.request_id,
        }
        encoded_quote = base64.b64encode(args.evidence.quote).decode("utf-8")
        token_req = TokenRequest(
            quote=encoded_quote,
            verifier_nonce=VerifierNonce(
                args.nonce.val, args.nonce.iat, args.nonce.signature
            ).__dict__,
            runtime_data=base64.b64encode(args.evidence.user_data.encode()).decode(
                "utf-8"
            ),
            policy_ids=args.policy_ids,
            event_log=args.evidence.event_log,
        )
        body = token_req.__dict__
        # body["runtime_data"] = base64.b64encode(body["runtime_data"].encode()).decode('utf-8')
        http_proxy = constants.HTTP_PROXY
        https_proxy = constants.HTTPS_PROXY
        proxies = {"http": http_proxy, "https": https_proxy}
        log.info("making attestation token request to ita ... : %s ", url)
        response = requests.post(
            url,
            headers=headers,
            data=json.dumps(body),
            proxies=proxies,
            timeout=self.cfg.retry_cfg.retry_wait_time,
        )
        response.raise_for_status()
        token_response = AttestationTokenResponse(token=response.json().get("token"))
        return GetTokenResponse(token_response.token, str(response.headers))

    def get_crl(self, crl_url):
        """This Function make get request to CRL Distribution point and return CRL Object.

        Args:
            crl_arr: list of crl distribution points
        """
        if crl_url == "":
            raise Exception("Invalid CRL URL present in the certificate")
        http_proxy = constants.HTTP_PROXY
        https_proxy = constants.HTTPS_PROXY
        proxies = {"http": http_proxy, "https": https_proxy}
        try:
            response = requests.get(crl_url, proxies=proxies)
            if response.status_code != http.HTTPStatus.OK:
                log.error("get_crl() failed with error: {}".format(response.content))
                return None
        except requests.exceptions.HTTPError as exc:
            log.error(f"Caught Http error in get_crl() http request: {exc}")
            return None
        except requests.exceptions.ConnectionError as exc:
            log.error(f"Caught Connection error in get_token() http request: {exc}")
            return None
        crl_obj = x509.load_der_x509_crl(response.content, default_backend())
        return crl_obj

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
        """This Function verify Attestation token issued by ITA

        Args:
            token: ITA Attestation Token
        """
        unverified_headers = jwt.get_unverified_header(token)
        kid = unverified_headers.get("kid", None)
        if kid is None:
            log.error("Missing key id in token")
            return None
        log.debug("kid : %s ", kid)

        # Get the JWT Signing Certificates from Intel Trust Authority
        try:
            jwks = self.get_token_signing_certificates()
        except requests.exceptions.HTTPError as exc:
            log.error(f"Caught Http Error in get_token_signing_certificates(): {exc}")
            return None
        if jwks == None:
            log.error("get_token_signing_certificates failed.")
            return None
        jwks_data = json.loads(jwks)
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

        cdp_list = inter_ca_cert.extensions.get_extension_for_oid(
            x509.ExtensionOID.CRL_DISTRIBUTION_POINTS
        )
        inter_ca_crl_url = cdp_list.value[0].full_name[0].value
        log.debug("inter ca crl url : %s", inter_ca_crl_url)
        try:
            inter_ca_crl_obj = self.get_crl(inter_ca_crl_url)
        except Exception as exc:
            log.error(f"Caught Exception in get_crl(): {exc}")
            return None

        if not self.verify_crl(inter_ca_crl_obj, inter_ca_cert, root_cert):
            log.error("Inter CA CRL is not valid")
            return None

        cdp_list = leaf_cert.extensions.get_extension_for_oid(
            x509.ExtensionOID.CRL_DISTRIBUTION_POINTS
        )
        leaf_crl_url = cdp_list.value[0].full_name[0].value
        log.debug("leaf crl url : %s", leaf_crl_url)
        try:
            leaf_crl_obj = self.get_crl(leaf_crl_url)
        except Exception as exc:
            log.error(f"Caught Exception in get_crl(): {exc}")
            return None
        if not self.verify_crl(leaf_crl_obj, leaf_cert, inter_ca_cert):
            log.error("Leaf CA CRL is not valid")
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
                f"Caught Exception in verifying inter ca certificate against root certificate : {exc}"
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
                f"Caught Exception in verifying leaf certificate against inter ca certificate : {exc}"
            )
            return None
        log.debug(
            "Leaf certificate verification against Root and Inter ca certificate Successful"
        )

        try:
            jwt.decode(token, leaf_cert.public_key(), unverified_headers.get("alg"))
        except jwt.ExpiredSignatureError:
            log.error("Token has expired.")
            return None
        except jwt.InvalidTokenError:
            log.error("Invalid token.")
            return None
        except Exception as exc:
            log.error(f"Caught Exception in Token Verification: {exc}")
            return None
        else:
            return jwt.decode(
                token, leaf_cert.public_key(), unverified_headers.get("alg")
            )

    def get_token_signing_certificates(self):
        """This Function retrieve token signing certificates from ITA"""
        url = urljoin(self.cfg.base_url, "certs")
        http_proxy = constants.HTTP_PROXY
        https_proxy = constants.HTTPS_PROXY
        proxies = {"http": http_proxy, "https": https_proxy}
        headers = {
            "Accept": "application/json",
        }
        log.debug("Making request to get_token_signing_certificates() url : %s", url)
        response = requests.get(
            url,
            headers=headers,
            proxies=proxies,
            timeout=self.cfg.retry_cfg.retry_wait_time,
        )
        response.raise_for_status()
        log.debug(
            "get_token_signing_certificates() response status code :%d",
            response.status_code,
        )
        jwks = response.content
        return jwks

    def attest(self, args: AttestArgs) -> AttestResponse:
        """This Function calls ITA Connector endpoints get_nonce(), collect evidence from adapter
           class, get_token() and return the attestation token.

        Args:
            AttestArgs: Instance of AttestArgs class

        Returns:
            AttestResponse: Instance of AttestResponse class
        """
        response = AttestResponse
        try:
            nonce_resp = self.get_nonce(GetNonceArgs(args.request_id))
        except requests.exceptions.HTTPError as exc:
            log.error(f"Caught Http Error in get_nonce(): {exc}")
            return None
        log.info("Nonce Retrieved Successfully")
        log.debug("Nonce : %s", nonce_resp.nonce)
        decoded_val = base64.b64decode(nonce_resp.nonce.val)
        decoded_iat = base64.b64decode(nonce_resp.nonce.iat)
        concatenated_nonce = decoded_val + decoded_iat
        evidence = args.adapter.collect_evidence(concatenated_nonce)
        if evidence == None:
            return None
        log.info("Quote : %s", base64.b64encode(evidence.quote).decode())
        try:
            token_resp = self.get_token(
                GetTokenArgs(
                    nonce_resp.nonce, evidence, args.policy_ids, args.request_id
                )
            )
        except requests.exceptions.HTTPError as exc:
            log.error(f"Caught Http Error in get_token(): {exc}")
            return None
        response.token = token_resp.token
        response.headers = token_resp.headers
        return response
