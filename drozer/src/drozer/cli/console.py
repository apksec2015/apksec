#!/usr/bin/python

import logging
import sys

from mwr.common import logger

from drozer.console import Console

logger.setLevel(logging.DEBUG)
logger.addStreamHandler()

sys.argv = ['drozer', 'console', 'connect']
Console().run(sys.argv[2::])
