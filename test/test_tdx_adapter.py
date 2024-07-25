"""
Copyright (c) 2024 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""

import unittest
from unittest.mock import patch, MagicMock, call


from inteltrustauthorityclient.tdx.tdx_adapter import TDXAdapter
from inteltrustauthorityclient.connector.evidence import Evidence


class TDXAdapterTestCase(unittest.TestCase):
    """Class TDXAdapterTestCase that inherits from unittest.TestCase"""

    def test_collect_evidence_with_nonce_and_user_data(self):
        """Test method to test collect_evidence with nonce and user_data"""
        tdx_adapter = TDXAdapter(user_data=b"user_data")
        with patch("os.path.exists") as mock_exists, patch(
            "tempfile.TemporaryDirectory"
        ) as mock_tempdir, patch("builtins.open", create=True) as mock_open, patch(
            "base64.b64encode"
        ) as mock_b64encode, patch(
            "os.rmdir"
        ) as mock_os_remove, patch(
            "hashlib.sha512"
        ) as mock_sha512:
            mock_sha512.return_value.digest.return_value = b"digest"
            mock_exists.return_value = True
            mock_os_remove.return_value = True
            mock_tempdir.return_value.__enter__.return_value = "tempdir"
            mock_open.side_effect = [
                MagicMock(write=MagicMock()),
                MagicMock(read=MagicMock()),
                MagicMock(read=MagicMock()),
                MagicMock(read=MagicMock()),
            ]

            mock_b64encode.return_value.decode.return_value = "quote"
            evidence = tdx_adapter.collect_evidence(nonce=b"nonce")
            mock_sha512.assert_called_once_with()
            calls = [call(b"nonce"), call(b"user_data")]
            mock_sha512.return_value.update.assert_has_calls(calls)

            calls = [call("/sys/kernel/config/tsm/report"), call("tempdir/inblob")]
            mock_exists.assert_has_calls(calls)
            mock_tempdir.assert_called_once_with(
                prefix="entry", dir="/sys/kernel/config/tsm/report"
            )
            mock_open.assert_has_calls(
                [
                    unittest.mock.call("tempdir/inblob", "wb"),
                    unittest.mock.call("tempdir/outblob", "rb"),
                    unittest.mock.call("tempdir/provider", "r", encoding="utf-8"),
                    unittest.mock.call("tempdir/generation", "r", encoding="utf-8"),
                ]
            )
            self.assertTrue(isinstance(evidence, Evidence))

    def test_collect_evidence_without_nonce_and_user_data(self):
        """Test method to test collect_evidence without nonce and user_data"""
        tdx_adapter = TDXAdapter()
        with patch("os.path.exists") as mock_exists, patch(
            "tempfile.TemporaryDirectory"
        ) as mock_tempdir, patch("builtins.open", create=True) as mock_open, patch(
            "base64.b64encode"
        ) as mock_b64encode, patch(
            "os.rmdir"
        ) as mock_os_remove, patch(
            "hashlib.sha512"
        ) as mock_sha512:
            mock_sha512.return_value.digest.return_value = b"digest"
            mock_exists.return_value = True
            mock_os_remove.return_value = True
            mock_tempdir.return_value.__enter__.return_value = "tempdir"
            mock_open.side_effect = [
                MagicMock(write=MagicMock()),
                MagicMock(read=MagicMock()),
                MagicMock(read=MagicMock()),
                MagicMock(read=MagicMock()),
            ]

            mock_b64encode.return_value.decode.return_value = "quote"
            evidence = tdx_adapter.collect_evidence()
            mock_sha512.assert_called_once_with()

            calls = [call("/sys/kernel/config/tsm/report"), call("tempdir/inblob")]
            mock_exists.assert_has_calls(calls)
            mock_tempdir.assert_called_once_with(
                prefix="entry", dir="/sys/kernel/config/tsm/report"
            )
            mock_open.assert_has_calls(
                [
                    unittest.mock.call("tempdir/inblob", "wb"),
                    unittest.mock.call("tempdir/outblob", "rb"),
                    unittest.mock.call("tempdir/provider", "r", encoding="utf-8"),
                    unittest.mock.call("tempdir/generation", "r", encoding="utf-8"),
                ]
            )
            self.assertTrue(isinstance(evidence, Evidence))

    def test_collect_evidence_with_tsm_dir_not_found(self):
        """Test method to test collect_evidence when TSM directory is not found"""
        tdx_adapter = TDXAdapter()
        with patch("hashlib.sha512") as mock_sha512, patch(
            "os.path.exists"
        ) as mock_exists, patch("logging.error") as mock_error:
            mock_sha512.return_value.digest.return_value = b"digest"
            mock_exists.return_value = False
            evidence = tdx_adapter.collect_evidence()
            mock_exists.assert_called_once_with("/sys/kernel/config/tsm/report")
            mock_error.assert_called_once_with(
                "Failed to fetch quote using Configfs TSM. Error: TSM directory not found."
            )
            self.assertIsNone(evidence)

    def test_collect_evidence_with_exception_in_tempdir_creation(self):
        """Test method to test collect_evidence with exception in creating report temporary directory"""
        tdx_adapter = TDXAdapter()
        with patch("hashlib.sha512") as mock_sha512, patch(
            "os.path.exists"
        ) as mock_exists, patch("tempfile.TemporaryDirectory") as mock_tempdir, patch(
            "logging.error"
        ) as mock_error:
            mock_sha512.return_value.digest.return_value = b"digest"
            mock_exists.return_value = True
            mock_tempdir.side_effect = Exception("Error creating tempdir")
            evidence = tdx_adapter.collect_evidence()
            mock_sha512.assert_called_once_with()
            mock_exists.assert_called_once_with("/sys/kernel/config/tsm/report")
            mock_error.assert_called_once_with(
                "Failed to fetch quote using Configfs TSM. Error: Caught exception in collect_evidence(): Error creating tempdir"
            )
            self.assertIsNone(evidence)

    def test_collect_evidence_with_report_file_not_present(self):
        """Test method to test collect_evidence with exception as report file not found"""
        tdx_adapter = TDXAdapter()
        with patch("hashlib.sha512") as mock_sha512, patch(
            "os.path.exists"
        ) as mock_exists, patch("tempfile.TemporaryDirectory") as mock_tempdir, patch(
            "logging.error"
        ) as mock_error:
            mock_sha512.return_value.digest.return_value = b"digest"
            mock_exists.return_value = True
            exception = FileNotFoundError("File is not present")
            exception.filename = "/sys/kernel/config/tsm/report/entry"
            mock_tempdir.side_effect = exception
            evidence = tdx_adapter.collect_evidence()
            mock_sha512.assert_called_once_with()
            mock_exists.assert_called_once_with("/sys/kernel/config/tsm/report")
            mock_error.assert_called_once_with(
                "Failed to fetch quote using Configfs TSM. Error: Caught FileNotFoundError exception in collect_evidence():/sys/kernel/config/tsm/report/entry"
            )
            self.assertIsNone(evidence)

    def test_collect_evidence_with_oserror_temp_file_creation(self):
        """Test method to test collect_evidence with OSError"""
        tdx_adapter = TDXAdapter()
        with patch("hashlib.sha512") as mock_sha512, patch(
            "os.path.exists"
        ) as mock_exists, patch("tempfile.TemporaryDirectory") as mock_tempdir, patch(
            "logging.error"
        ) as mock_error:
            mock_sha512.return_value.digest.return_value = b"digest"
            mock_exists.return_value = True
            mock_tempdir.side_effect = OSError("Unable to create temp file")
            evidence = tdx_adapter.collect_evidence()
            mock_sha512.assert_called_once_with()
            mock_exists.assert_called_once_with("/sys/kernel/config/tsm/report")
            mock_error.assert_called_once_with(
                "Failed to fetch quote using Configfs TSM. Error: Caught OSError exception in collect_evidence(): Unable to create temp file"
            )
            self.assertIsNone(evidence)

    def test_collect_evidence_with_ValueError_incorrect_filename(self):
        """Test method to test collect_evidence with ValueError"""
        tdx_adapter = TDXAdapter()
        with patch("hashlib.sha512") as mock_sha512, patch(
            "os.path.exists"
        ) as mock_exists, patch("tempfile.TemporaryDirectory") as mock_tempdir, patch(
            "logging.error"
        ) as mock_error:
            mock_sha512.return_value.digest.return_value = b"digest"
            mock_exists.return_value = True
            mock_tempdir.side_effect = ValueError("incorrect file name")
            evidence = tdx_adapter.collect_evidence()
            mock_sha512.assert_called_once_with()
            mock_exists.assert_called_once_with("/sys/kernel/config/tsm/report")
            mock_error.assert_called_once_with(
                "Failed to fetch quote using Configfs TSM. Error: Caught ValueError exception in collect_evidence(): incorrect file name"
            )
            self.assertIsNone(evidence)

    def test_collect_evidence_with_no_inblob(self):
        """Test method to test collect_evidence with no inblob file created."""
        tdx_adapter = TDXAdapter()
        with patch("os.path.exists") as mock_exists, patch(
            "tempfile.TemporaryDirectory"
        ) as mock_tempdir, patch("builtins.open", create=True) as mock_open, patch(
            "base64.b64encode"
        ) as mock_b64encode, patch(
            "os.rmdir"
        ) as mock_os_remove, patch(
            "hashlib.sha512"
        ) as mock_sha512, patch(
            "logging.error"
        ) as mock_error:
            mock_sha512.return_value.digest.return_value = b"digest"
            mock_exists.side_effect = [
                True,
                False,
            ]
            mock_os_remove.return_value = True
            mock_tempdir.return_value.__enter__.return_value = "tempdir"
            mock_open.side_effect = [
                MagicMock(write=MagicMock()),
                MagicMock(read=MagicMock()),
                MagicMock(read=MagicMock()),
                MagicMock(read=MagicMock()),
            ]

            mock_b64encode.return_value.decode.return_value = "quote"
            evidence = tdx_adapter.collect_evidence()
            mock_sha512.assert_called_once_with()
            calls = [call("/sys/kernel/config/tsm/report"), call("tempdir/inblob")]
            mock_exists.assert_has_calls(calls)
            mock_tempdir.assert_called_once_with(
                prefix="entry", dir="/sys/kernel/config/tsm/report"
            )
            mock_error.assert_called_once_with(
                "Failed to fetch quote using Configfs TSM. Error: Caught exception in collect_evidence(): Inblob file not found under directory: tempdir"
            )
            self.assertIsNone(evidence)

    def test_collect_evidence_with_outblob_exception_while_opening(self):
        """Test method to test collect_evidence with opening outblob file for reading quote."""
        tdx_adapter = TDXAdapter()
        with patch("os.path.exists") as mock_exists, patch(
            "tempfile.TemporaryDirectory"
        ) as mock_tempdir, patch("builtins.open", create=True) as mock_open, patch(
            "os.rmdir"
        ) as mock_os_remove, patch(
            "hashlib.sha512"
        ) as mock_sha512, patch(
            "logging.error"
        ) as mock_error:
            mock_sha512.return_value.digest.return_value = b"digest"
            mock_exists.return_value = True
            mock_os_remove.return_value = True
            mock_tempdir.return_value.__enter__.return_value = "tempdir"
            mock_open.side_effect = [
                MagicMock(write=MagicMock()),
                Exception("Error in opening outblob file"),
                MagicMock(read=MagicMock()),
                MagicMock(read=MagicMock()),
            ]

            evidence = tdx_adapter.collect_evidence()
            mock_sha512.assert_called_once_with()

            calls = [call("/sys/kernel/config/tsm/report"), call("tempdir/inblob")]
            mock_exists.assert_has_calls(calls)
            mock_tempdir.assert_called_once_with(
                prefix="entry", dir="/sys/kernel/config/tsm/report"
            )
            mock_error.assert_called_once_with(
                "Failed to fetch quote using Configfs TSM. Error: Caught exception in collect_evidence(): Error in opening outblob file: Error in opening outblob file"
            )
            self.assertIsNone(evidence)


if __name__ == "__main__":
    unittest.main()
