"""
Copyright (c) 2024 Intel Corporation
All rights reserved.
SPDX-License-Identifier: BSD-3-Clause
"""

import os
import logging

def setup_logging():
    logging_level = os.environ.get("LOGGING_LEVEL", "INFO").upper()
    numeric_level = getattr(logging, logging_level, None)
    if not isinstance(numeric_level, int):
        raise ValueError(f"Invalid log level: {logging_level}")
    
    logging.basicConfig(level=numeric_level, format="%(asctime)s [%(levelname)s]: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S")
