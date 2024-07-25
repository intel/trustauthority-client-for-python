"""
Copyright (c) 2024 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""

import os
import tempfile
import logging as log
from dataclasses import dataclass
from inteltrustauthorityclient.resources import constants as const


@dataclass
class Request:
    """
    Request represents a request for an attestation report.

    Attributes:
        _in_blob (bytearray): The input blob.
        _get_aux_blob (bool): A flag indicating whether to get the auxiliary blob.
    """

    _in_blob: bytearray
    _get_aux_blob: bool


@dataclass
class Response:
    """
    Represents a response object containing attestation report.
    Attributes:
        _provider (str): The provider of the response.
        _out_blob (bytearray): The output blob of the response.
        _aux_blob (bytearray): The auxiliary blob of the response.
    """

    _provider: str
    _out_blob: bytearray
    _aux_blob: bytearray

    @property
    def provider(self):
        return self._provider

    @property
    def out_blob(self):
        return self._out_blob

    @property
    def aux_blob(self):
        return self._aux_blob


class Report:
    """
    Provides an API to the configfs/tsm/report subsystem for collecting attestation reports
    """

    tsm_subsystem_path = "/sys/kernel/config/tsm/report"

    def get_report(self, request: Request) -> Response:
        """
        Retrieves a report based on the given request from configfs-tsm.

        Args:
            request (Request): The request object containing the input data.

        Returns:
            Response: The response object containing the report.

        Raises:
            FileNotFoundError: If any file or directory required for the report is not found.
            OSError: If there is an error in reading or writing files.
            ValueError: If there is an error in the value of a variable.
            Exception: If any other exception occurs.
        """
        provider = None
        generation = None
        td_quote = None

        if not os.path.exists(self.tsm_subsystem_path):
            raise Exception("TSM directory not found.")

        try:
            with tempfile.TemporaryDirectory(
                prefix="entry", dir=self.tsm_subsystem_path
            ) as tempdir:
                log.debug(f"Creating tempdir {tempdir} to request report")
                # Check if configfs-tsm inblob file is present
                if not os.path.exists(os.path.join(tempdir, "inblob")):
                    os.rmdir(tempdir)
                    raise Exception(f"Inblob file not found under directory: {tempdir}")

                with open(os.path.join(tempdir, "inblob"), "wb") as inblob_file:
                    inblob_file.write(request._in_blob)

                # Read the output of quote and prevent case of resource busy
                try:
                    with open(os.path.join(tempdir, "outblob"), "rb") as outblob_file:
                        td_quote = outblob_file.read()
                except OSError as e:
                    raise OSError(f"Read outblob failed with OSError: {str(e)}")
                except Exception as e:
                    raise Exception(f"Error in opening outblob file: {str(e)}")

                # Read provider info
                with open(
                    os.path.join(tempdir, "provider"), "r", encoding="utf-8"
                ) as provider_file:
                    provider = provider_file.read()

                # Read generation info
                with open(
                    os.path.join(tempdir, "generation"), "r", encoding="utf-8"
                ) as generation_file:
                    generation = generation_file.read()
                # Check if the outblob has been corrupted during file open
                if int(generation) > 1:
                    raise Exception(
                        f"report generation was {int(generation)} when expecting 1 while reading subtree"
                    )

                os.rmdir(tempdir)
            if td_quote is not None:
                return Response(provider, td_quote, None)
            return None

        except FileNotFoundError as e:
            raise FileNotFoundError(
                f"Caught FileNotFoundError exception in collect_evidence():{str(e.filename)}"
            )
        except OSError as e:
            raise OSError(f"Caught OSError exception in collect_evidence(): {str(e)}")
        except ValueError as e:
            raise ValueError(
                f"Caught ValueError exception in collect_evidence(): {str(e)}"
            )
        except Exception as e:
            raise Exception(f"Caught exception in collect_evidence(): {str(e)}")
