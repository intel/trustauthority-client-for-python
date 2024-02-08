"""
Copyright (c) 2024 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""

import base64
import json
import jwt
import requests
from datetime import datetime
from src.connector.evidence import Evidence
from src.resources import constants as constants
from src.tdx.tdx_adapter import TDXAdapter
from urllib.parse import urljoin
from uuid import UUID
from typing import List
from dataclasses import dataclass
from cryptography import x509
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
    adapter : TDXAdapter()
    policy_ids : List[UUID]
    request_id : str


@dataclass
class AttestResponse:
    token: str
    headers: str


@dataclass
class EvidenceParams:
    type: int
    Evidence: Evidence
    user_data: bytearray
    eventLog: bytearray


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
    quote: bytearray                    #'json:"quote"'
    verifier_nonce: VerifierNonce    #'json:"verifier_nonce"'
    runtime_data: str              #'json:"runtime_data"'
    policy_ids: List[UUID]      #'json:"policy_ids"'
    event_log: str                 #'json:"event_log"'


class ITAConnector:
    """ 
    This class creates connector to ITA and provide api endpoints for methods like 
    get_nonce(), get_token(), get_token_signing_certificates(), verify_token() 
    """
    
    def __init__(self, cfg) -> None:
        """Initializes ita connector object

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
        print(url)
        headers = {
            'x-api-key': self.cfg.api_key,
            'Accept': 'application/json',
            'request-id': args.request_id,
        }
        try:
            resp = requests.get(url, headers=headers)
            nonce_data = resp.json()
            nonce = VerifierNonce(nonce_data.get('val'), nonce_data.get('iat'), nonce_data.get('signature'))
            nonce_response = GetNonceResponse(resp.headers, nonce)
            #print(nonce_response)
            return nonce_response
        except Exception as e:
            print(e)

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
        base64_quote = base64.b64encode(args.evidence.quote).decode('utf-8')
        treq = TokenRequest(
           quote = base64_quote,
           verifier_nonce = VerifierNonce(args.nonce.val, args.nonce.iat, args.nonce.signature).__dict__,
           runtime_data = args.evidence.user_data,
           policy_ids = args.policy_ids,
           event_log = args.evidence.event_log,
        )
        body = treq.__dict__
        body["runtime_data"] = base64.b64encode(body["runtime_data"].encode()).decode('utf-8')
        http_proxy  = constants.HTTP_PROXY
        https_proxy = constants.HTTPS_PROXY
        proxies = {
              "http"  : http_proxy,
              "https" : https_proxy
            }
        try:
            print("making attestation token request to ita ... ",url)
            response = requests.post(url, headers=headers, data=json.dumps(body), proxies=proxies)
        except requests.exceptions.HTTPError as eh:
            print("Exception: ", eh)
        except requests.exceptions.ConnectionError as ec:
            print(ec)
        try:
            token_response = AttestationTokenResponse(token=response.json().get("token"))
            return GetTokenResponse(token_response.token, str(response.headers))
        except Exception as e:
            print ("Json exception :", e)


    def get_crl(self, crl_arr):
        """This Function make get request to get crl array.

        Args:
            crl_arr: list of crl distribution points
        """
        if len(crl_arr) < 1:
            raise Exception("Invalid CDP count present in the certificate")
        crl_url = crl_arr[0]
        try:
            resp = requests.get(crl_url)
        except requests.exceptions.HTTPError as eh:
            print("Exception: ", eh)
        except requests.exceptions.ConnectionError as ec:
            print(ec)
        crl_bytes = resp.content
        crl_obj = x509.load_der_x509_crl(crl_bytes, default_backend())
        return crl_obj

    def verify_crl(self, crl, leaf_cert, ca_cert):
        """This Function verify certificate against crl

        Args:
            crl: crl object
            leaf_cert: leaf certificate
            ca_cert: ca certificate
        """
        if leaf_cert is None or ca_cert is None or crl is None:
            raise Exception("Leaf Cert, CA Cert, or CRL is None")
        # Checking CRL signed by CA Certificate
        try:
            ca_cert.public_key().verify(
                crl.signature,
                crl.tbs_certlist_bytes,
                padding.PKCS1v15(),
                crl.signature_hash_algorithm,
            )
        except Exception as e:
            raise Exception("CRL signature verification failed") from e
        if crl.next_update < datetime.utcnow():
            raise Exception("Outdated CRL")
        for r_cert in crl:
            if r_cert.serial_number == leaf_cert.serial_number:
                raise Exception("Certificate was Revoked")

    def verify_token(self, token):
        """This Function verify Attestation token issued by ITA

        Args:
            token: ITA Attestation Token
        """
        unverified_headers = jwt.get_unverified_header(token)
        kid = unverified_headers.get('kid', None)
        if kid is None:
            raise Exception("Missing key id in token")
        print("kid : ",kid)

        # Get the JWT Signing Certificates from Intel Trust Authority
        jwks = self.get_token_signing_certificates()
        jwks_data = json.loads(jwks)
        print(jwks_data)
        for key in jwks_data.get("keys", []):
            print("key found: ", key.get("kid"))
            if key.get("kid") == kid:
                print("kid found")
                x5c_certificate = key.get("x5c", [])[0]
                cert_bytes = base64.b64decode(x5c_certificate)
                cert = x509.load_pem_x509_certificate(cert_bytes, default_backend())
                print(cert)
                public_key = cert.public_key().public_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PublicFormat.SubjectPublicKeyInfo
                ).decode("utf-8")

        if public_key:
            print(f"Public key for kid:\n{public_key}")
        else:
            print(f"Public key for kid not found.")

        return public_key


        # for jwk in jwks['keys']:
        #     #kid = jwk['kid']
        #     #print("kid: \n", kid)
        #     try:
        #         public_key = jwt.algorithms.RSAAlgorithm.from_jwk(json.dumps(jwk))
        #         public_keys[jwk['kid']] = public_key
        #         print(public_keys)
        #     except KeyError:
        #         print("key does not exist")

        # kid = jwt.get_unverified_header(token)['kid']

        # jwk_key = public_key
        # #jwk_key = public_keys.get_key_by_kid(kid)
        # print(jwk_key)
        # #jwk_key = public_keys[kid]
        # #jwk_key = jwk[kid]

        # #payload = jwt.decode(token, key=jwk_key, algorithms=['RS256'])
        # #print(payload)
        # #jwk_key = jwk_set.get_key_by_kid(kid)
        # if jwk_key:
        #     # Verify the cert chain. x5c field in the JWKS would contain the cert chain
        #     ats_certs = jwk_key.x5c

        # else:
        #     raise Exception("Could not find Key matching the key id")

        # root = x509.CertificateRevocationList()
        # intermediate = x509.CertificateRevocationList()
        # leaf_cert = None
        # inter_ca_cert = None
        # root_cert = None

        # for ats_cert_data in ats_certs:
        #     ats_cert = x509.load_pem_x509_certificate(ats_cert_data.encode(), default_backend())

        #     if ats_cert.issuer == ats_cert.subject and ats_cert.serial_number == 0:
        #         root.add_cert(ats_cert)
        #         root_cert = ats_cert
        #     elif ats_cert.issuer != ats_cert.subject and ats_cert.basic_constraints.ca:
        #         intermediate.add_cert(ats_cert)
        #         inter_ca_cert = ats_cert
        #     else:
        #         leaf_cert = ats_cert

        # root_crl = self.get_crl(root_cert.crl_distribution_points)
        # self.verify_crl(root_crl, inter_ca_cert, root_cert)

        # ats_crl = self.get_crl(leaf_cert.crl_distribution_points)
        # self.verify_crl(ats_crl, leaf_cert, inter_ca_cert)

        # # Verify the Leaf certificate against the CA
        # opts = x509.VerifyOptions(
        #     purpose=x509.Purpose.SERVER_AUTH,
        #     trust_store=x509.CertificateStore([root]),
        #     intermediate_store=x509.CertificateStore([intermediate]),
        # )

        # leaf_cert.public_key().verify(leaf_cert.signature, leaf_cert.tbs_certificate_bytes, padding.PKCS1v15(), leaf_cert.signature_hash_algorithm, opts)

        # # Extract the public key from JWK using exponent and modulus
        # pub_key = jwk_key.public_key()
        # return pub_key

    def get_token_signing_certificates(self):
        """This Function retrieve token signing certificates from ITA"""

        print("-> connector.get_token_signing_certificate()...\n")
        url = urljoin(self.cfg.base_url, "certs")
        headers = {
            'Accept': 'application/json',
        }
        try:
            response = requests.get(url, headers=headers)
            jwks = response.content
            return jwks
        except Exception as e:
            print(e)

    def attest(self, args: AttestArgs) -> AttestResponse:
        """This Function calls ITA Connector endpoints get_nonce(), collect evidence from adapter
           class, get_token() and return the attestation token. 

        Args:
            AttestArgs: Instance of AttestArgs class

        Returns:
            AttestResponse: Instance of AttestResponse class
        """
        response = AttestResponse
        nonce_resp = self.get_nonce(GetNonceArgs(args.request_id))
        response.headers = nonce_resp.headers
        print("Nonce : ",nonce_resp.nonce, end = '\n\n')
        decoded_val = base64.b64decode(nonce_resp.nonce.val)
        decoded_iat = base64.b64decode(nonce_resp.nonce.iat)
        concatenated_nonce = decoded_val + decoded_iat
        evidence = args.adapter.collect_evidence(concatenated_nonce)
        print("Quote :", evidence.quote, end = '\n\n')
        token_resp = self.get_token(GetTokenArgs(nonce_resp.nonce, evidence, args.policy_ids, args.request_id))
        response.token = token_resp.token
        response.headers = token_resp.headers
        return response