"""
Copyright (c) 2024 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""

import os
import json
import unittest
import requests
from unittest.mock import patch, MagicMock
from src.connector.connector import *
from src.connector.config import *
from src.tdx.tdx_adapter import TDXAdapter


def get_connector():
    """This function initializes and returns Intel Trust Authority connector object"""
    retryConfig = RetryConfig(2, 2, 2)
    config = Config(
        retryConfig,
        "https://custom-base-url-ITA.com",
        "https://custom-api-url-ITA.com",
        "apikey",
    )
    ita_connector = ITAConnector(config)
    return ita_connector


class ConnectorTestCase(unittest.TestCase):
    """class ConnectorTestCase that inherits from unittest.TestCase"""

    ita_c = get_connector()
    ita_c.nonce_url = "self.ita_c.nonce_url"
    ita_c.token_url = "self.ita_c.token_url"
    mocked_nonce = {
        "val": "g9QC7VxV0n8dID0zSJeVLSULqYCJuv4iMepby91xukrhXgKrKscGXB5lxmT2s3POjxVOG+fSPCYpOKYWRRWAyQ==",
        "iat": "MjAyMi0wOC0yNCAxMjozNjozMi45Mjk3MjIwNzUgKzAwMDAgVVRD",
        "signature": "WswVG3rOPJIuVmMNG2GZ6IF4hD+QfuJ/PigIRaHtQitGAHRCRzgtW8+8UbXe9vJfjnapjw7RQyzpT+vPGVpxRSoiBaj54RsedI38K9ubFd3gPvsMlYltgFRSAtb1ViWZxMhL0yA9+xzgv0D+11mpNEz8nt3HK4oALV5EAxqJYCmKZRzi3/LJe842AY8DVcV9eUZQ8RBx7gNe72Ex1fU3+qF9A9MuOgKqJ41/7HFTY0rCpcBS8k6E1VBSatk4XTj5KNcluI3LoAOvBuiwObgmNKT8Nyc4JAEc+gmf9e9taIgt7QNFEtl3nwPQuiCLIh0FHdXPYumiQ0mclU8nfQL8ZUoe/GqgOd58+fZoHeGvFoeyjQ7Q0Ini1rWEzwOY5gik9yH57/JTEJTI8Evc0L8ggRO4M/sZ2ZTyIq5yRUISB2eDh6qTfbKgSr5LpxW8IRl0y9fp8CEuzhFxKcOeld9p61yb040P+QhemhP/O1E5tf4y4Pz/ISASiKUBFSTh4yYx",
    }

    mocked_token_response = {
        "token": "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6IjNmZDc1MWYyZTBkMGY1Mjg0NmMwZWNkNDk3MmM2ZTk5ZGZjNjQyMDUxY2QzMzlkZDliMDQzODFhZjhjMGRkYjgwNDUxNGE3YTFmZWU0NjczYWM4NDRmZDVkYjdmMTVmYiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.Mj4nQgujHiGidoRBkCzVtU6V7RAxD8PxFEpcMWkHHuLe_ZHamT1Sqnpn21JxaT6todQ3L21LAOIKzua_Zcuy-g91UCd501RqGTYQMP2EfoEZYk5uuiNmT37VpPSXSLSiRKAaNzjidpmiaoFkvNgupl8OWKJ9__4CA3W_EAw60mWcbU95ApvQz8m1VWTIGR4si7XMt1qUaPdS7Ey446W6RzU1wr9OAWhnPDLgffKH6ORYLGriBR6gAgCda1tmjMC6WtBZcqr0ub8R7_cfMn8qUsyiOjrQfyjw_3feJ5ooYqofY7Vq6YCzjvw_GSDxq5Ircbsnrm--ggK8FIJ6f6H1EEfZ-kw9Unocbew2Bul2xIM1wyyXvRtL9NDWiiGTL-IEqLqTBm5UBFuZ2VmZA1au0X1HaMDEBSWwWoE31xzGhZd3mYWpbWV7sDnJpJIIkPfHrh-J0e_aUQZfqUFp5uksBClTO7OTqrnV1F_JJXV_BhKdzj1w_esojOIuyypuR2Awr9Rbdx_mtX0gEgN-Cg8eOB46xYDVx50HWMs1HsBki3LFl0bynkpMXRcIKdc8aQDTKv3O-Wvt0PQ6Vf_F0zKy6Nms7gLGsuCSGoNbAFwAu0NkMHMwOYSbeLK7ijyLnOBPv4UDmk6h1L4HopX5OPe1o2qwCWCGpcTPWsJARKqoKx4"
    }

    mocked_cert_data = {
        "keys": [
            {
                "alg": "PS384",
                "e": "AQAB",
                "kid": "3fd751f2e0d0f52846c0ecd4972c6e99dfc642051cd339dd9b04381af8c0ddb804514a7a1fee4673ac844fd5db7f15fb",
                "kty": "RSA",
                "n": "vKKV7v7czOHapQ22ZnW677i4BkQIuxVTLk933javfZyLzpM7ZP_Mhvu9QqHrr-iKEqCDBuX1slL_hoB0fTCGGnoFTZ1lTqBdmhFysIgg5uzAqMWL2SJdzYX9RJ_ZXMFnvzTznO-b2jJd864pUI6y72mrzfTqQvgw_60fa3tjc9zjJPiqT1yadKar3G5c0fJqg7AUooTuMkIq291tHqoNhfYzzshZCSFV_d5RruheVMjvgMunx1zISiZ5RNRjcy39G7-08UTCIlSKE_GdsLDNViHqACz60BW3p-kSY5YdoslwKvDUOJnkVZMpJNfdYDoBIiIGgKL2j5H8arHmhSw1A1kl66YdDl7H5Pa46qp4B2FrS5Qpt1D9C-SZXkWN3wzDIQLsHKs0e86R5guLMS9_WcfsPCcHCLjqMZe6S-18SdjwzCK4hbn5vLCZYUzIyVEIcYT8f3mS3s3I1UxJRW53WZOEKkyGVKKGTF8uRxaksFVGrIdW0Q41Wo3mB30N2tqL",
                "x5c": [
                    "MIIE/DCCA2SgAwIBAgIBATANBgkqhkiG9w0BAQ0FADBhMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExGjAYBgNVBAoMEUludGVsIENvcnBvcmF0aW9uMSkwJwYDVQQDDCBEZXZlbG9wbWVudCBBbWJlciBBVFMgU2lnbmluZyBDQTAeFw0yMzA3MDcwOTQ1MTVaFw0yNDA3MDYwOTQ1MTVaMGwxCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEaMBgGA1UECgwRSW50ZWwgQ29ycG9yYXRpb24xNDAyBgNVBAMMK0RldmVsb3BtZW50IEFtYmVyIEF0dGVzdGF0aW9uIFRva2VuIFNpZ25pbmcwggGiMA0GCSqGSIb3DQEBAQUAA4IBjwAwggGKAoIBgQC8opXu/tzM4dqlDbZmdbrvuLgGRAi7FVMuT3feNq99nIvOkztk/8yG+71Coeuv6IoSoIMG5fWyUv+GgHR9MIYaegVNnWVOoF2aEXKwiCDm7MCoxYvZIl3Nhf1En9lcwWe/NPOc75vaMl3zrilQjrLvaavN9OpC+DD/rR9re2Nz3OMk+KpPXJp0pqvcblzR8mqDsBSihO4yQirb3W0eqg2F9jPOyFkJIVX93lGu6F5UyO+Ay6fHXMhKJnlE1GNzLf0bv7TxRMIiVIoT8Z2wsM1WIeoALPrQFben6RJjlh2iyXAq8NQ4meRVkykk191gOgEiIgaAovaPkfxqseaFLDUDWSXrph0OXsfk9rjqqngHYWtLlCm3UP0L5JleRY3fDMMhAuwcqzR7zpHmC4sxL39Zx+w8JwcIuOoxl7pL7XxJ2PDMIriFufm8sJlhTMjJUQhxhPx/eZLezcjVTElFbndZk4QqTIZUooZMXy5HFqSwVUash1bRDjVajeYHfQ3a2osCAwEAAaOBszCBsDAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBTjQ4pQOmjW6jIKg5w2lIaHlmix7zAfBgNVHSMEGDAWgBRe9XoBzt6MDePrZXOGVsaW8IPWKzALBgNVHQ8EBAMCBPAwUwYDVR0fBEwwSjBIoEagRIZCaHR0cHM6Ly9hbWJlci1kZXYyLXVzZXI1LnByb2plY3QtYW1iZXItc21hcy5jb20vY3JsL2F0cy1jYS1jcmwuZGVyMA0GCSqGSIb3DQEBDQUAA4IBgQAy8YhuaumtWuRUZX1AjAgC0ObG1zccs6dNn3Rza12Z+53GfYtcO4LelOryyhWOaPbU/nB+7pCKrvAG1PAiS3+UHWLyc3FPAKE8nKInFa8Fl5s0epceWqeEGYSPVY1TpKTjnQiDfVuUJGWujl0gdheQR8Ui1bZC1IEmvsE9y/qGsYHXydfRxZa8w23xvAQqJERyX4w6ninwzuiztL2xtdlx4VuLH4lb3wN0/CxARSWkAbEi3uhwuCTsxUw1gx/Zsf/vGzDJj5EbgDKZTJxLRdazkEq8upXOH2+W42I6TlJWOCpiPQ0mH0f5i5fPjyg78dDeZNvC4bTtx2H79G54qVlQfdZxaEx0+fPm+LHtndb4CFeY7sGD+6e2pbldlNsUiuLUcrcUKkD2fLjVqqZeAhXMpv+aVXJvVPWGWcWRg5Oj1kXgQ2UyZ6NI3T/eG6dbGEhen/FyD4eHv0SdPyMLamHSM2iAI4KWDxC9PjvUzkaVrgKKr7El994A6SOduTmFoF8=",
                    "MIIFCjCCA3KgAwIBAgIBATANBgkqhkiG9w0BAQ0FADBwMSIwIAYDVQQDDBlEZXZlbG9wbWVudCBBbWJlciBSb290IENBMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExFDASBgNVBAcMC1NhbnRhIENsYXJhMRowGAYDVQQKDBFJbnRlbCBDb3Jwb3JhdGlvbjAeFw0yMzA3MDcwOTM4NDhaFw0zNjEyMzAwOTM4NDhaMGExCzAJBgNVBAYTAlVTMQswCQYDVQQIDAJDQTEaMBgGA1UECgwRSW50ZWwgQ29ycG9yYXRpb24xKTAnBgNVBAMMIERldmVsb3BtZW50IEFtYmVyIEFUUyBTaWduaW5nIENBMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAqwu9IEnNWJ/TWq/4qlL8SfppAOC/wCBo0GSxYUFvXXHUKIGCzTRTLxeNtGfMB9JolrT+XGFUFDhW8NuNH27uQBe4pKfqw6+IMkoH6qIGxidZmixM5pRA/VfVjJUthHhCewFjvw+Qv1uGppVeb6skHXzL5Ur3s9Sav3d9GXDymzdK+ehrxYPABfluBu12AQrKM+zQdr/MjT48YGO50nDEDcYQqVC0yPaMl3WuKW0KVq9dkkNyHcxWujRX/JNoQ8eeQ5XhzBTmSveakpUH+5dCWAEAnXrZ0Vsy8BI3tA1BfR9JAImjRZa6xclVr0pUGw/w+y5ZsVYjiqkbkeqqutjr+VBDUwZ87TgzeDwsSzDGoGfEhGh2VHoUpppKf6wSjZ/n/AgmYcXxz6JI5i3P8hCiocxG4Ml6HzYalP8flugWDqPRyxARFtBUojUyY23NfKFMOjwuI8AXelBVJ+To42Wp1+E5WlLkD9shlc/NA+Lp/SHmNpJMYFG+9YDeW7EuJ92JAgMBAAGjgb0wgbowEgYDVR0TAQH/BAgwBgEB/wIBADAdBgNVHQ4EFgQUXvV6Ac7ejA3j62VzhlbGlvCD1iswHwYDVR0jBBgwFoAUdHM5jGouqIdfqdKI/necaI73rw4wDgYDVR0PAQH/BAQDAgEGMFQGA1UdHwRNMEswSaBHoEWGQ2h0dHBzOi8vYW1iZXItZGV2Mi11c2VyNS5wcm9qZWN0LWFtYmVyLXNtYXMuY29tL2NybC9yb290LWNhLWNybC5kZXIwDQYJKoZIhvcNAQENBQADggGBAFK76xCGZ2dYRSOReiimAxGVT131A7nPM2Ecxc9YpwAooDTk2yA60Qj3RZYqBzO8HJAZfJwjcsEVKngXgku7gSYBbKR3sHbXSxjiBTLWHCfedbJK4zXXQ52UMRj8Ade8cPx7jtP0DlJ5iZVMTx1unDkCyZBsNJWCEWQcKcPbgRl/24+32uxYRHgFt5QTMFjheffkg7HQwz6nIKCI2jrc/PDWUaqmkyQ8gMmyP9oI9CLX7MLg0E4faZcYyYFNMziJMWYXs6PWUkIauWGVfMwtjy1WCy9iGiCSrHm6PdUx/N02VLaUITryQi66m3DkpZQRFd0kt7qvaZ2I81/KY6Ajgb2p3jRmWZIkxiBdwP//4URL4frZ9NQrqvK5C3HTEBEWpvRwOUXluDu0EPe5uOAWa/HSrfS3sRNdyFSJQjp4CAN6H6tJyU7TzZB4LNQ6RqRWYLfywZjon+karjBSkSkRIov3Xns7fY8QPUBDlcQnT7yL5DtDNxl/rbUIq7stXOF7Pg==",
                    "MIIE0TCCAzmgAwIBAgIUPSD2LbZdFmXI1Ww+d3SeH+93QUwwDQYJKoZIhvcNAQENBQAwcDEiMCAGA1UEAwwZRGV2ZWxvcG1lbnQgQW1iZXIgUm9vdCBDQTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRQwEgYDVQQHDAtTYW50YSBDbGFyYTEaMBgGA1UECgwRSW50ZWwgQ29ycG9yYXRpb24wHhcNMjMwNzA3MDkzNzAwWhcNNDkxMjMwMDkzNzAwWjBwMSIwIAYDVQQDDBlEZXZlbG9wbWVudCBBbWJlciBSb290IENBMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExFDASBgNVBAcMC1NhbnRhIENsYXJhMRowGAYDVQQKDBFJbnRlbCBDb3Jwb3JhdGlvbjCCAaIwDQYJKoZIhvcNAQEBBQADggGPADCCAYoCggGBAL3nxzqexbSXgvLp+RNwA2w+b0X4G4Oqtu6mBWbq+GYTiQVi8Lch6NBO2QaF9WaCaSD4Sbx17yfMLO1v6p4hihjWHS1uODSDpXzUFYCuusfKL2hLWe8T6cNTNhgJWsQPJ2awTUQUJD6LpMLmos/jUb37/461kj/GsBy2/B5s1ZD3O9qnra8ElADLsiAkBAQP7Ke5WkVn9yW1bwHis1CfQsTNXirw9AiOOxgVYuIugZBddkDk3tIB8KfRpC4Fs8xOpciiBhIiCbvq0zAqWlTl2bJ510wiu+Fi3I7lF3dPk36y6xfq15SWNPTbyIbxh5Jx1eDu88JhlWDChBReKDPcS+LWDqwR15r+31kMhVnS631GCQKk/tREcnv3bEpu3NoNuo27tDUTAtooBCh/PUtqMNcOmKW90dSLE2wwNx/SkVaeRfQ+IEHA4jfwKyxnQ06NYQXP/4LrSkCv9Cob9fjk7x3c/kX0esmwDHAWBF3PZ/cfbE6SWExlDkWezVuA2aG3OwIDAQABo2MwYTAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBR0czmMai6oh1+p0oj+d5xojvevDjAfBgNVHSMEGDAWgBR0czmMai6oh1+p0oj+d5xojvevDjAOBgNVHQ8BAf8EBAMCAQYwDQYJKoZIhvcNAQENBQADggGBADXAJh/40oZWABchJuzRPdIZzt0ZRl/GqOytPU4Y/YYPiINq80TtVCqbYd/DhajCPWpzEXRybJoCKhBAJpig3v0FbdoVkA7Tt5bfpnHlySo5NsVeM/AEerMmH+p206pQ6cFmBqdy2gcEZO5t7iJ5m2cJpPVDEUqGbExggx6zU+sc5G9e1hSROsJZ49PMVQSH0wlFNzMuqN/RRSDobWfoLSAFSITM61NO/9ngCEf4iaLGuuHKdd1/28gHj19mHL9db5nWEo3Mkathx0IBQFH7Sw7bCv8wMnUgdazy2iTFsiPAX3Hl2De/KlzhGTiONCtY7/cBIRbm6tN1g4Byo86waQ5HpLUkU+Skzov8l6G3nRYoH2aDfNr02p0cR96tRsUmteVom+s6oiBbruHM84lemX+OFFy/wbfcKl3oQxDSpLlW+8PZ8Isqd4QUv8lKRg4+GbWb7IeZq8057fO6BvVX29wQvCfityEk2EVkzrDT+U9ILunIt5tTqQBt+m9mE3XNEQ==",
                ],
            }
        ]
    }

    def test_get_nonce(self):
        """Test method to test get_nonce() from Intel Trust Authority Connector"""
        nonceargs = GetNonceArgs("1234")
        with patch("requests.get", url="self.ita_c.nonce_url") as mock_get:
            mocked_response = requests.Response()
            mocked_response.json = lambda: self.mocked_nonce
            mocked_response.status_code = 200
            mock_get.return_value = mocked_response
            nonce = self.ita_c.get_nonce(nonceargs)
            assert (
                nonce.nonce.val.replace(".", "") == self.mocked_nonce["val"]
                and nonce.nonce.iat.replace(".", "") == self.mocked_nonce["iat"]
                and nonce.nonce.signature == self.mocked_nonce["signature"]
            )

    def test_get_nonce_connection_error(self):
        """Test method to test get_nonce() with raising Connection Error"""
        nonceargs = GetNonceArgs("1234")
        with patch("requests.get", url="self.ita_c.nonce_url") as mocked_request:
            mocked_request.side_effect = requests.exceptions.ConnectionError
            nonce = self.ita_c.get_nonce(nonceargs)
            assert nonce is None

    def test_get_nonce_http_error(self):
        """Test method to test get_nonce() with raising HTTP Error"""
        nonceargs = GetNonceArgs("1234")
        with patch("requests.get") as mocked_request:
            mocked_response = requests.Response()
            mocked_response.status_code = 400
            mocked_request.return_value = mocked_response
            nonce = self.ita_c.get_nonce(nonceargs)
            self.assertIsNone(nonce)

    def test_get_nonce_timeout_error(self):
        """Test method to test get_nonce() with raising Timeout Error"""
        nonceargs = GetNonceArgs("1234")
        with patch("requests.get", url="self.ita_c.nonce_url") as mocked_request:
            mocked_request.side_effect = requests.exceptions.Timeout
            nonce = self.ita_c.get_nonce(nonceargs)
            assert nonce is None

    def test_get_nonce_request_exception(self):
        """Test method to test get_nonce() with raising Request Exception"""
        nonceargs = GetNonceArgs("1234")
        with patch("requests.get", url="self.ita_c.nonce_url") as mocked_request:
            mocked_request.side_effect = requests.exceptions.RequestException
            nonce = self.ita_c.get_nonce(nonceargs)
            assert nonce is None

    def test_get_token(self):
        """Test method to test get_token() from Intel Trust Authority Connector"""
        verifier_nonce = VerifierNonce("g9QC7Vx", "g9QC7Vx", "g9QC7Vx")
        evidence_params = Evidence(0, b"quotedata", "", "")
        tokenargs = GetTokenArgs(verifier_nonce, evidence_params, [], "1234")
        with patch("requests.post", url="self.ita_c.token_url") as mocked_get:
            mocked_response = requests.Response()
            mocked_response.json = lambda: self.mocked_token_response
            mocked_response.status_code = 200
            mocked_get.return_value = mocked_response
            token = self.ita_c.get_token(tokenargs)
            assert token.token == self.mocked_token_response["token"]

    def test_get_token_invalid_policyid(self):
        """Test method to test get_token() with Invalid UUID's"""
        verifier_nonce = VerifierNonce("g9QC7Vx", "g9QC7Vx", "g9QC7Vx")
        evidence_params = Evidence(0, b"quotedata", "", "")
        tokenargs = GetTokenArgs(verifier_nonce, evidence_params, ["1234-5678"], "1234")
        token = self.ita_c.get_token(tokenargs)
        assert token is None

    def test_get_token_connection_error(self):
        """Test method to test get_token() with raising Connection Error"""
        verifier_nonce = VerifierNonce("g9QC7Vx", "g9QC7Vx", "g9QC7Vx")
        evidence_params = Evidence(0, b"quotedata", "", "")
        tokenargs = GetTokenArgs(verifier_nonce, evidence_params, [], "1234")
        with patch("requests.post", url="self.ita_c.token_url") as mocked_request:
            mocked_request.side_effect = requests.exceptions.ConnectionError
            token = self.ita_c.get_token(tokenargs)
            assert token is None

    def test_get_token_http_error(self):
        """Test method to test get_token() with raising HTTP Error"""
        verifier_nonce = VerifierNonce("g9QC7Vx", "g9QC7Vx", "g9QC7Vx")
        evidence_params = Evidence(0, b"quotedata", "", "")
        tokenargs = GetTokenArgs(verifier_nonce, evidence_params, [], "1234")
        with patch("requests.post", url="self.ita_c.token_url") as mocked_request:
            mocked_response = requests.Response()
            mocked_response.status_code = 400
            mocked_request.return_value = mocked_response
            token = self.ita_c.get_token(tokenargs)
            assert token is None

    def test_get_token_timeout_error(self):
        """Test method to test get_token() with raising Timeout Error"""
        verifier_nonce = VerifierNonce("g9QC7Vx", "g9QC7Vx", "g9QC7Vx")
        evidence_params = Evidence(0, b"quotedata", "", "")
        tokenargs = GetTokenArgs(verifier_nonce, evidence_params, [], "1234")
        with patch("requests.post", url="self.ita_c.token_url") as mocked_request:
            mocked_request.side_effect = requests.exceptions.Timeout
            token = self.ita_c.get_token(tokenargs)
            assert token is None

    def test_get_token_request_exception(self):
        """Test method to test get_token() with raising Request Exception"""
        verifier_nonce = VerifierNonce("g9QC7Vx", "g9QC7Vx", "g9QC7Vx")
        evidence_params = Evidence(0, b"quotedata", "", "")
        tokenargs = GetTokenArgs(verifier_nonce, evidence_params, [], "1234")
        with patch("requests.post", url="self.ita_c.token_url") as mocked_request:
            mocked_request.side_effect = requests.exceptions.RequestException
            token = self.ita_c.get_token(tokenargs)
            assert token is None

    def test_get_token_signing_certificates(self):
        """Test method to test get_token_signing_certificates() from Intel Trust Authority Connector"""
        with patch("requests.get", url="certs") as mocked_request:
            mocked_response = requests.Response()
            mocked_response.json = lambda: self.mocked_cert_data
            mocked_response.status_code = 200
            mocked_request.return_value = mocked_response
            cert_data = self.ita_c.get_token_signing_certificates()
            assert cert_data == self.mocked_cert_data

    def test_get_token_signing_certificates_connection_error(self):
        """Test method to test get_token_signing_certificates() with raising Connection Error"""
        with patch("requests.get", url="certs") as mocked_request:
            mocked_response = requests.Response()
            mocked_response.status_code = 400
            mocked_request.return_value = mocked_response
            mocked_request.side_effect = requests.exceptions.ConnectionError
            token_signing_certificates = self.ita_c.get_token_signing_certificates()
            assert token_signing_certificates is None

    def test_get_token_signing_certificates_http_error(self):
        """Test method to test get_token_signing_certificates() with raising HTTP Error"""
        with patch("requests.get", url="certs") as mocked_request:
            mocked_response = requests.Response()
            mocked_response.status_code = 400
            mocked_request.return_value = mocked_response
            token_signing_certificates = self.ita_c.get_token_signing_certificates()
            assert token_signing_certificates is None

    def test_get_token_signing_certificates_timeout_error(self):
        """Test method to test get_token_signing_certificates() with raising Timeout Error"""
        with patch("requests.get", url="certs") as mocked_request:
            mocked_request.side_effect = requests.exceptions.Timeout
            token_signing_certificates = self.ita_c.get_token_signing_certificates()
            assert token_signing_certificates is None

    def test_get_token_signing_certificates_request_exception(self):
        """Test method to test get_token_signing_certificates() with raising Request Exception"""
        with patch("requests.get", url="certs") as mocked_request:
            mocked_request.side_effect = requests.exceptions.RequestException
            token_signing_certificates = self.ita_c.get_token_signing_certificates()
            assert token_signing_certificates is None

    def mock_get_crl(arg1, arg2):
        return ""

    def mock_verify_crl(arg1, arg2, arg3, arg4):
        return True

    def mock_get_nonce(arg1, arg2):
        return GetNonceResponse(
            "",
            VerifierNonce(
                "g9QC7VxV0n8dID0zSJeVLSULqYCJuv4iMepby91xukrhXgKrKscGXB5lxmT2s3POjxVOG+fSPCYpOKYWRRWAyQ==",
                "MjAyMi0wOC0yNCAxMjozNjozMi45Mjk3MjIwNzUgKzAwMDAgVVRD",
                "WswVG3rOPJIuVmMNG2GZ6IF4hD+QfuJ/PigIRaHtQitGAHRCRzgtW8+8UbXe9vJfjnapjw7RQyzpT+vPGVpxRSoiBaj54RsedI38K9ubFd3gPvsMlYltgFRSAtb1ViWZxMhL0yA9+xzgv0D+11mpNEz8nt3HK4oALV5EAxqJYCmKZRzi3/LJe842AY8DVcV9eUZQ8RBx7gNe72Ex1fU3+qF9A9MuOgKqJ41/7HFTY0rCpcBS8k6E1VBSatk4XTj5KNcluI3LoAOvBuiwObgmNKT8Nyc4JAEc+gmf9e9taIgt7QNFEtl3nwPQuiCLIh0FHdXPYumiQ0mclU8nfQL8ZUoe/GqgOd58+fZoHeGvFoeyjQ7Q0Ini1rWEzwOY5gik9yH57/JTEJTI8Evc0L8ggRO4M/sZ2ZTyIq5yRUISB2eDh6qTfbKgSr5LpxW8IRl0y9fp8CEuzhFxKcOeld9p61yb040P+QhemhP/O1E5tf4y4Pz/ISASiKUBFSTh4yYx",
            ),
        )

    def test_verify_token(self):
        """Test method to test verify_token() from Intel Trust Authority Connector"""
        with patch("requests.get", url="certs") as mocked_certs_request:
            mocked_certs_response = requests.Response()
            mocked_certs_response.json = lambda: self.mocked_cert_data
            mocked_certs_response.status_code = 200
            mocked_certs_request.return_value = mocked_certs_response
            with patch.object(ITAConnector, "get_crl", new=self.mock_get_crl):
                with patch.object(ITAConnector, "verify_crl", new=self.mock_verify_crl):
                    with patch(
                        "cryptography.x509.Certificate.public_key"
                    ) as mock_public_key:
                        mock_verify = mock_public_key.return_value.verify
                        mock_verify.return_value = True
                        with patch("jwt.decode") as mock_decode:
                            mock_decode.return_value = None
                            decoded_token = self.ita_c.verify_token(
                                self.mocked_token_response["token"]
                            )
                            assert decoded_token is None

    def test_verify_token_invalid_get_certs(self):
        """Test method to test verify_token() with Invalid Certificate"""
        with patch("requests.get", url="certs") as mocked_certs_request:
            mocked_certs_response = requests.Response()
            mocked_certs_response.json = lambda: None
            mocked_certs_response.status_code = 200
            mocked_certs_request.return_value = mocked_certs_response
            decoded_token = self.ita_c.verify_token(self.mocked_token_response["token"])
            assert decoded_token is None

    def test_verify_token_jwt_expired_signature_error(self):
        """Test method to test verify_token() with raising JWT Signature Expired Error"""
        with patch("requests.get", url="certs") as mocked_certs_request:
            mocked_certs_response = requests.Response()
            mocked_certs_response.json = lambda: self.mocked_cert_data
            mocked_certs_response.status_code = 200
            mocked_certs_request.return_value = mocked_certs_response
            with patch.object(ITAConnector, "get_crl", new=self.mock_get_crl):
                with patch.object(ITAConnector, "verify_crl", new=self.mock_verify_crl):
                    with patch("cryptography.x509.Certificate.public_key") as mock_pk:
                        mock_pk.return_value.verify.side_effect = InvalidSignature(
                            "mock exception"
                        )
                        with patch("jwt.decode") as mock_decode:
                            mock_decode.side_effect = jwt.ExpiredSignatureError(
                                "mock exception"
                            )
                            decoded_token = self.ita_c.verify_token(
                                self.mocked_token_response["token"]
                            )
                            assert decoded_token is None
                        decoded_token = self.ita_c.verify_token(
                            self.mocked_token_response["token"]
                        )
                        assert decoded_token is None

    def test_verify_token_jwt_invalid_token_error(self):
        """Test method to test verify_token() with raising JWT Invalid Token Error"""
        with patch("requests.get", url="certs") as mocked_certs_request:
            mocked_certs_response = requests.Response()
            mocked_certs_response.json = lambda: self.mocked_cert_data
            mocked_certs_response.status_code = 200
            mocked_certs_request.return_value = mocked_certs_response
            with patch.object(ITAConnector, "get_crl", new=self.mock_get_crl):
                with patch.object(ITAConnector, "verify_crl", new=self.mock_verify_crl):
                    with patch("cryptography.x509.Certificate.public_key") as mock_pk:
                        mock_pk.return_value.verify.side_effect = InvalidSignature(
                            "mock exception"
                        )
                        with patch("jwt.decode") as mock_decode:
                            mock_decode.side_effect = jwt.InvalidTokenError(
                                "mock exception"
                            )
                            decoded_token = self.ita_c.verify_token(
                                self.mocked_token_response["token"]
                            )
                            assert decoded_token is None
                        decoded_token = self.ita_c.verify_token(
                            self.mocked_token_response["token"]
                        )
                        assert decoded_token is None

    def test_verify_token_jwt_decode_exception(self):
        """Test method to test verify_token() with raising JWT Decode Exception"""
        with patch("requests.get", url="certs") as mocked_certs_request:
            mocked_certs_response = requests.Response()
            mocked_certs_response.json = lambda: self.mocked_cert_data
            mocked_certs_response.status_code = 200
            mocked_certs_request.return_value = mocked_certs_response
            with patch.object(ITAConnector, "get_crl", new=self.mock_get_crl):
                with patch.object(ITAConnector, "verify_crl", new=self.mock_verify_crl):
                    with patch("cryptography.x509.Certificate.public_key") as mock_pk:
                        mock_pk.return_value.verify.side_effect = InvalidSignature(
                            "Signature not valid"
                        )
                        with patch("jwt.decode") as mock_decode:
                            mock_decode.side_effect = Exception("mock exception")
                            decoded_token = self.ita_c.verify_token(
                                self.mocked_token_response["token"]
                            )
                            assert decoded_token is None
                        decoded_token = self.ita_c.verify_token(
                            self.mocked_token_response["token"]
                        )
                        assert decoded_token is None

    def test_attest(self):
        """Test method to test attest() of Intel Trust Authority Connector"""
        attest_args = AttestArgs(TDXAdapter(""))

        def mock_collect_evidence(arg1, arg2):
            return Evidence(0, b"BAACAIEAAAAAAAAAk5pyM", "", None)

        def mock_get_token(arg1, arg2):
            return GetTokenResponse("", "")

        with patch.object(ITAConnector, "get_nonce", new=self.mock_get_nonce):
            with patch.object(
                TDXAdapter, "collect_evidence", new=mock_collect_evidence
            ):
                with patch.object(ITAConnector, "get_token", new=mock_get_token):
                    decoded_token = self.ita_c.attest(attest_args)
                    assert decoded_token is not None

    def test_attest_invalid_policyid(self):
        """Test method to test attest() with Invalid policyid"""
        attest_args = AttestArgs(TDXAdapter(""), "", ["1234-5678"])
        decoded_token = self.ita_c.attest(attest_args)
        assert decoded_token is None

    def test_attest_empty_nonce(self):
        """Test method to test attest() with empty Nonce"""
        token = "eyJhbGciOiJQUzM4NCIsInR5cCI6IkpXVCIsImtpZCI6IjNmZDc1MWYyZTBkMGY1Mjg0NmMwZWNkNDk3MmM2ZTk5ZGZjNjQyMDUxY2QzMzlkZDliMDQzODFhZjhjMGRkYjgwNDUxNGE3YTFmZWU0NjczYWM4NDRmZDVkYjdmMTVmYiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.Mj4nQgujHiGidoRBkCzVtU6V7RAxD8PxFEpcMWkHHuLe_ZHamT1Sqnpn21JxaT6todQ3L21LAOIKzua_Zcuy-g91UCd501RqGTYQMP2EfoEZYk5uuiNmT37VpPSXSLSiRKAaNzjidpmiaoFkvNgupl8OWKJ9__4CA3W_EAw60mWcbU95ApvQz8m1VWTIGR4si7XMt1qUaPdS7Ey446W6RzU1wr9OAWhnPDLgffKH6ORYLGriBR6gAgCda1tmjMC6WtBZcqr0ub8R7_cfMn8qUsyiOjrQfyjw_3feJ5ooYqofY7Vq6YCzjvw_GSDxq5Ircbsnrm--ggK8FIJ6f6H1EEfZ-kw9Unocbew2Bul2xIM1wyyXvRtL9NDWiiGTL-IEqLqTBm5UBFuZ2VmZA1au0X1HaMDEBSWwWoE31xzGhZd3mYWpbWV7sDnJpJIIkPfHrh-J0e_aUQZfqUFp5uksBClTO7OTqrnV1F_JJXV_BhKdzj1w_esojOIuyypuR2Awr9Rbdx_mtX0gEgN-Cg8eOB46xYDVx50HWMs1HsBki3LFl0bynkpMXRcIKdc8aQDTKv3O-Wvt0PQ6Vf_F0zKy6Nms7gLGsuCSGoNbAFwAu0NkMHMwOYSbeLK7ijyLnOBPv4UDmk6h1L4HopX5OPe1o2qwCWCGpcTPWsJARKqoKx4"
        attest_args = AttestArgs(TDXAdapter(""), "")

        def mock_get_nonce(arg1, arg2):
            return None

        with patch.object(ITAConnector, "get_nonce", new=mock_get_nonce):
            decoded_token = self.ita_c.attest(attest_args)
            assert decoded_token is None

    def test_attest_empty_collect_evidence(self):
        """Test method to test attest() with empty Evidence"""
        attest_args = AttestArgs(TDXAdapter(""))

        def mock_get_nonce(arg1, arg2):
            return GetNonceResponse(
                "",
                VerifierNonce(
                    "g9QC7VxV0n8dID0zSJeVLSULqYCJuv4iMepby91xukrhXgKrKscGXB5lxmT2s3POjxVOG+fSPCYpOKYWRRWAyQ==",
                    "MjAyMi0wOC0yNCAxMjozNjozMi45Mjk3MjIwNzUgKzAwMDAgVVRD",
                    "WswVG3rOPJIuVmMNG2GZ6IF4hD+QfuJ/PigIRaHtQitGAHRCRzgtW8+8UbXe9vJfjnapjw7RQyzpT+vPGVpxRSoiBaj54RsedI38K9ubFd3gPvsMlYltgFRSAtb1ViWZxMhL0yA9+xzgv0D+11mpNEz8nt3HK4oALV5EAxqJYCmKZRzi3/LJe842AY8DVcV9eUZQ8RBx7gNe72Ex1fU3+qF9A9MuOgKqJ41/7HFTY0rCpcBS8k6E1VBSatk4XTj5KNcluI3LoAOvBuiwObgmNKT8Nyc4JAEc+gmf9e9taIgt7QNFEtl3nwPQuiCLIh0FHdXPYumiQ0mclU8nfQL8ZUoe/GqgOd58+fZoHeGvFoeyjQ7Q0Ini1rWEzwOY5gik9yH57/JTEJTI8Evc0L8ggRO4M/sZ2ZTyIq5yRUISB2eDh6qTfbKgSr5LpxW8IRl0y9fp8CEuzhFxKcOeld9p61yb040P+QhemhP/O1E5tf4y4Pz/ISASiKUBFSTh4yYx",
                ),
            )

        def mock_collect_evidence(arg1, arg2):
            return None

        with patch.object(ITAConnector, "get_nonce", new=mock_get_nonce):
            with patch.object(
                TDXAdapter, "collect_evidence", new=mock_collect_evidence
            ):
                decoded_token = self.ita_c.attest(attest_args)
                assert decoded_token is None

    def test_attest_empty_get_token(self):
        """Test method to test attest() with empty Token"""
        attest_args = AttestArgs(TDXAdapter(""))

        def mock_collect_evidence(arg1, arg2):
            return Evidence(0, b"BAACAIEAAAAAAAAAk5pyM", "", None)

        def mock_get_token(arg1, arg2):
            return None

        with patch.object(ITAConnector, "get_nonce", new=self.mock_get_nonce):
            with patch.object(
                TDXAdapter, "collect_evidence", new=mock_collect_evidence
            ):
                with patch.object(ITAConnector, "get_token", new=mock_get_token):
                    decoded_token = self.ita_c.attest(attest_args)
                    assert decoded_token is None


if __name__ == "__main__":
    unittest.main()
