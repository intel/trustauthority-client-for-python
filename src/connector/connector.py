"""
Copyright (c) 2024 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""

import base64
import json
import jwt
import requests
import logging as log
from datetime import *
from src.resources import logging as logger
from src.connector.evidence import Evidence
from src.resources import constants as constants
from src.tdx.tdx_adapter import TDXAdapter
from urllib.parse import urljoin
from uuid import UUID
from typing import List
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
        http_proxy  = constants.HTTP_PROXY
        https_proxy = constants.HTTPS_PROXY
        proxies = {
              "http"  : http_proxy,
              "https" : https_proxy
            }
        try:
            response = requests.get(url, headers=headers, proxies=proxies, timeout=self.cfg.retry_cfg.retryWaitTime)
            if response.status_code != 200:
                allowed_retries = self.cfg.retry_cfg.retryMax
                while allowed_retries > 0:
                    response = requests.get(url, headers=headers, proxies=proxies, timeout=self.cfg.retry_cfg.retryWaitTime)
                    allowed_retries -= 1
                    if response.status_code == 200 or allowed_retries == 0:
                        break
                if response.status_code != 200:
                    log.error("get_nonce() failed with error: {}".format(response.content))
                    return None
            nonce_data = response.json()
            nonce = VerifierNonce(nonce_data.get('val'), nonce_data.get('iat'), nonce_data.get('signature'))
            nonce_response = GetNonceResponse(response.headers, nonce)
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
            response = requests.post(url, headers=headers, data=json.dumps(body), proxies=proxies, timeout=self.cfg.retry_cfg.retryWaitTime)
            if response.status_code != 200:
                allowed_retries = self.cfg.retry_cfg.retryMax
                while allowed_retries > 0:
                    response = requests.post(url, headers=headers, data=json.dumps(body), proxies=proxies, timeout=self.cfg.retry_cfg.retryWaitTime)
                    allowed_retries -= 1
                    if response.status_code == 200 or allowed_retries == 0:
                        break
                if response.status_code != 200:
                    log.error("get_token() failed with error: {}".format(response.content))
                    return None
        except requests.exceptions.HTTPError as eh:
            print("Exception: ", eh)
        except requests.exceptions.ConnectionError as ec:
            print(ec)
        try:
            token_response = AttestationTokenResponse(token=response.json().get("token"))
            return GetTokenResponse(token_response.token, str(response.headers))
        except Exception as e:
            print ("Json exception :", e)


    def get_crl(self, crl_url):
        """This Function make get request to get crl array.

        Args:
            crl_arr: list of crl distribution points
        """
        if crl_url == "":
            raise Exception("Invalid CRL URL present in the certificate")
        http_proxy  = constants.HTTP_PROXY
        https_proxy = constants.HTTPS_PROXY
        proxies = {
                "http"  : http_proxy,
                "https" : https_proxy
                }
        try:
            response = requests.get(crl_url, proxies = proxies)
            if response.status_code != 200:
                log.error("get_crl() failed with error: {}".format(response.content))
                return None
        except requests.exceptions.HTTPError as eh:
            print("Exception: ", eh)
        except requests.exceptions.ConnectionError as ec:
            print(ec)
        crl_obj = x509.load_der_x509_crl(response.content, default_backend())
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
        pub_key = ca_cert.public_key()
        if not(crl.is_signature_valid(pub_key)):
            log.error("Invalid certificate signature")
            return False
        dt = datetime.now(timezone.utc) 
        utc_time = dt.replace(tzinfo=timezone.utc) 
        utc_timestamp = utc_time.timestamp()
        if(crl.next_update_utc.timestamp() < utc_timestamp):
            log.error("crl has been expired")
            return False
        if(crl.get_revoked_certificate_by_serial_number(leaf_cert.serial_number) != None):
            log.error("certificate has been revoked")
            return False
        return True

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
        if jwks == None:
            return None
        jwks_data = json.loads(jwks)
        print(jwks_data)
        for key in jwks_data.get("keys", []):
            print("key found: ", key.get("kid"))
            x5c_certificates = key.get("x5c", [])
            
        root = []
        intermediate = []
        leaf_cert = None
        inter_ca_cert = None
        root_cert = None

        for cert in x5c_certificates:
            # print(cert)
            cert_inter = load_der_x509_certificate(base64.b64decode(cert))
            for attribute in cert_inter.subject:
                if(attribute.oid == x509.NameOID.COMMON_NAME):
                    common_name_subject = attribute.value
            for attribute in cert_inter.issuer:
                if(attribute.oid == x509.NameOID.COMMON_NAME):
                    common_name_issuer = attribute.value
            if common_name_subject == common_name_issuer and common_name_subject.find("Root CA") != -1:
                root.append(cert_inter)
                root_cert = cert_inter
            elif common_name_subject != common_name_issuer and common_name_subject.find("Signing CA") != -1:
                intermediate.append(cert_inter)
                inter_ca_cert = cert_inter
            else:
                leaf_cert = cert_inter
        print(root, intermediate)

        cdp_list = inter_ca_cert.extensions.get_extension_for_oid(x509.ExtensionOID.CRL_DISTRIBUTION_POINTS)
        for cdp in cdp_list.value:
            for dp in cdp.full_name:
                print("CRL Distribution Point:", dp.value)
                inter_ca_crl_url = dp.value
        print("inter ca crl url :", dp.value)
        inter_ca_crl_obj = self.get_crl(inter_ca_crl_url)
        if not self.verify_crl(inter_ca_crl_obj, inter_ca_cert, root_cert):
            log.error("Inter CA CRL is not valid")
            return None

        cdp_list = leaf_cert.extensions.get_extension_for_oid(x509.ExtensionOID.CRL_DISTRIBUTION_POINTS)
        for cdp in cdp_list.value:
            for dp in cdp.full_name:
                print("CRL Distribution Point:", dp.value)
                leaf_crl_url = dp.value
        print("leaf crl url :",leaf_crl_url)
        leaf_crl_obj = self.get_crl(leaf_crl_url)
        if not self.verify_crl(leaf_crl_obj, leaf_cert, inter_ca_cert):
            log.error("Leaf CA CRL is not valid")
            return None
        
        try:
            jwt.decode(token, leaf_cert.public_key(), unverified_headers.get('alg'))
        except jwt.ExpiredSignatureError:
            log.exception("Token has expired.")
        except jwt.InvalidTokenError:
            log.exception("Invalid token.")
        except Exception as exc:
            log.exception(f"Caught Exception in Token Verification: {exc}")
        else:
            return leaf_cert.public_key()
        

    def get_token_signing_certificates(self):
        """This Function retrieve token signing certificates from ITA"""
        url = urljoin(self.cfg.base_url, "certs")
        http_proxy  = constants.HTTP_PROXY
        https_proxy = constants.HTTPS_PROXY
        proxies = {
              "http"  : http_proxy,
              "https" : https_proxy
            }
        headers = {
            'Accept': 'application/json',
        }
        try:
            print(url)
            response = requests.get(url, headers=headers, proxies=proxies, timeout=self.cfg.retry_cfg.retryWaitTime)
            if response.status_code != 200:
                allowed_retries = self.cfg.retry_cfg.retryMax
                while allowed_retries > 0:
                    response = requests.get(url, headers=headers, proxies=proxies, timeout=self.cfg.retry_cfg.retryWaitTime)
                    allowed_retries -= 1
                    if response.status_code == 200 or allowed_retries == 0:
                        break
                if response.status_code != 200:
                    log.error("get_nonce() failed with error: {}".format(response.content))
                    return None
            print(response.status_code)
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
        if nonce_resp == None:
            return None
        response.headers = nonce_resp.headers
        print("Nonce : ",nonce_resp.nonce, end = '\n\n')
        decoded_val = base64.b64decode(nonce_resp.nonce.val)
        decoded_iat = base64.b64decode(nonce_resp.nonce.iat)
        concatenated_nonce = decoded_val + decoded_iat
        evidence = args.adapter.collect_evidence(concatenated_nonce)
        if evidence == None:
            return None
        print("Quote :", evidence.quote, end = '\n\n')
        token_resp = self.get_token(GetTokenArgs(nonce_resp.nonce, evidence, args.policy_ids, args.request_id))
        if token_resp == None:
            return None
        response.token = token_resp.token
        response.headers = token_resp.headers
        return response