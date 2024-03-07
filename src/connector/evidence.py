"""
Copyright (c) 2024 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""


class Evidence:
    """Contains the attributes to be sent for attestation of platform."""

    def __init__(
        self,
        type: int,
        quote: bytearray,
        user_data: bytearray,
        runtime_data: bytearray,
        event_log: bytearray,
        adapter_type: str,
    ) -> None:
        self._type = type
        self._quote = quote
        self._user_data = user_data
        self._runtime_data = runtime_data
        self._event_log = event_log
        self.adapter_type = adapter_type

    @property
    def type(self):
        """Getter method."""
        return self._type

    @property
    def quote(self):
        return self._quote

    @property
    def user_data(self):
        """Getter method."""
        return self._user_data

    @property
    def event_log(self):
        """Getter method."""
        return self._event_log

    @property
    def runtime_data(self):
        """Getter method."""
        return self._runtime_data
