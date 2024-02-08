"""
Copyright (c) 2024 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""


import json
import unittest
from src.connector.connector import *
from src.connector.config import *

def get_connector():
    retryConfig = RetryConfig()
    config = Config("https://localhost:8080",retryConfig,"https://localhost:8080","apikey")
    ita_connector = ITAConnector(config)
    return ita_connector


class ConnectorTestCase(unittest.TestCase):
    def test_get_nonce(self):
        ita_c = get_connector()
        nonceargs=GetNonceArgs("1234")
        nonce = ita_c.get_nonce(nonceargs)
        assert nonce.nonce.val == "g9QC7VxV0n8dID0zSJeVLSULqYCJuv4iMepby91xukrhXgKrKscGXB5lxmT2s3POjxVOG+fSPCYpOKYWRRWAyQ==" and nonce.nonce.iat == "MjAyMi0wOC0yNCAxMjozNjozMi45Mjk3MjIwNzUgKzAwMDAgVVRD" \
            and nonce.nonce.signature == "WswVG3rOPJIuVmMNG2GZ6IF4hD+QfuJ/PigIRaHtQitGAHRCRzgtW8+8UbXe9vJfjnapjw7RQyzpT+vPGVpxRSoiBaj54RsedI38K9ubFd3gPvsMlYltgFRSAtb1ViWZxMhL0yA9+xzgv0D+11mpNEz8nt3HK4oALV5EAxqJYCmKZRzi3/LJe842AY8DVcV9eUZQ8RBx7gNe72Ex1fU3+qF9A9MuOgKqJ41/7HFTY0rCpcBS8k6E1VBSatk4XTj5KNcluI3LoAOvBuiwObgmNKT8Nyc4JAEc+gmf9e9taIgt7QNFEtl3nwPQuiCLIh0FHdXPYumiQ0mclU8nfQL8ZUoe/GqgOd58+fZoHeGvFoeyjQ7Q0Ini1rWEzwOY5gik9yH57/JTEJTI8Evc0L8ggRO4M/sZ2ZTyIq5yRUISB2eDh6qTfbKgSr5LpxW8IRl0y9fp8CEuzhFxKcOeld9p61yb040P+QhemhP/O1E5tf4y4Pz/ISASiKUBFSTh4yYx"

    def test_get_token(self):
        ita_c = get_connector()
        verifier_nonce = VerifierNonce("g9QC7Vx","g9QC7Vx","g9QC7Vx")
        evidence_params = EvidenceParams(0,"","","")
        tokenargs = GetTokenArgs(verifier_nonce,evidence_params,[],"1234")
        token = ita_c.get_token(tokenargs)
        assert token.token == "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6IjNmZDc1MWYyZTBkMGY1Mjg0NmMwZWNkNDk3MmM2ZTk5ZGZjNjQyMDUxY2QzMzlkZDliMDQzODFhZ"

    def test_get_certs(self):
        ita_c = get_connector()
        certs = ita_c.get_token_signing_certificates()
        decoded_string = certs.decode('utf-8')
        certs_json = json.loads(decoded_string)
        # print(certs_json)
        assert len(certs_json['keys']) == 1
        # assert certs_json['cert'] == {"keys":[{"alg":"PS384","e":"AQAB","kid":"3ac844fd5db7f15fb","kty":"RSA","n":"sFVGrIdW0Q41Wo3mB30N2tqL","x5c":["6SOduTmFoF8=","/rbUIq7stXOF7Pg==","BnIt5tTqQBt+m9mE3XNEQ=="]}]}

    # def test_verify_token(self):
    #     ita_c = get_connector()
    #     token = "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6IjNmZDc1MWYyZTBkMGY1Mjg0NmMwZWNkNDk3MmM2ZTk5ZGZjNjQyMDUxY2QzMzlkZDliMDQzODFhZjhjMGRkYjgwNDUxNGE3YTFmZWU0NjczYWM4NDRmZDVkYjdmMTVmYiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.Mj4nQgujHiGidoRBkCzVtU6V7RAxD8PxFEpcMWkHHuLe_ZHamT1Sqnpn21JxaT6todQ3L21LAOIKzua_Zcuy-g91UCd501RqGTYQMP2EfoEZYk5uuiNmT37VpPSXSLSiRKAaNzjidpmiaoFkvNgupl8OWKJ9__4CA3W_EAw60mWcbU95ApvQz8m1VWTIGR4si7XMt1qUaPdS7Ey446W6RzU1wr9OAWhnPDLgffKH6ORYLGriBR6gAgCda1tmjMC6WtBZcqr0ub8R7_cfMn8qUsyiOjrQfyjw_3feJ5ooYqofY7Vq6YCzjvw_GSDxq5Ircbsnrm--ggK8FIJ6f6H1EEfZ-kw9Unocbew2Bul2xIM1wyyXvRtL9NDWiiGTL-IEqLqTBm5UBFuZ2VmZA1au0X1HaMDEBSWwWoE31xzGhZd3mYWpbWV7sDnJpJIIkPfHrh-J0e_aUQZfqUFp5uksBClTO7OTqrnV1F_JJXV_BhKdzj1w_esojOIuyypuR2Awr9Rbdx_mtX0gEgN-Cg8eOB46xYDVx50HWMs1HsBki3LFl0bynkpMXRcIKdc8aQDTKv3O-Wvt0PQ6Vf_F0zKy6Nms7gLGsuCSGoNbAFwAu0NkMHMwOYSbeLK7ijyLnOBPv4UDmk6h1L4HopX5OPe1o2qwCWCGpcTPWsJARKqoKx4"
    #     pub_key = ita_c.verify_token(token)
    #     assert 10 == 11
        
if __name__ == '__main__':
    unittest.main()