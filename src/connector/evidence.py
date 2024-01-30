"""
Copyright (c) 2024 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""


class Evidence:
    """Contains the attributes to be sent for attestation of platform."""

    def __init__(self, type:int, quote:bytearray, user_data:bytearray, event_log:bytearray) -> None:
        self._type = type
        self._quote = quote
        self._user_data = user_data
        self._event_log = event_log

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
