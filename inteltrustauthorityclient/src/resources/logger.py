"""
Copyright (c) 2024 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""

import os
import logging


def setup_logging():
    """This function sets the log level to value provided by user or default value as INFO

    Raises:
        ValueError: Value error is raised if the log level is not within values defined by logging.
    """
    log_level = os.environ.get("LOGGING_LEVEL", "INFO").upper()
    numeric_level = getattr(logging, log_level, None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {log_level}")

    logging.basicConfig(
        level=numeric_level,
        format="[%(levelname)s] :: %(asctime)s :: {%(pathname)s:%(lineno)d} :: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    print(f"log level set to: ", log_level)
