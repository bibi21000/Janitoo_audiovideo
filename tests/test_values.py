# -*- coding: utf-8 -*-

"""Unittests for Janitoo-common.
"""
__license__ = """
    This file is part of Janitoo.

    Janitoo is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Janitoo is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with Janitoo. If not, see <http://www.gnu.org/licenses/>.

"""
__author__ = 'Sébastien GALLET aka bibi21000'
__email__ = 'bibi21000@gmail.com'
__copyright__ = "Copyright © 2013-2014-2015-2016 Sébastien GALLET aka bibi21000"

import warnings
warnings.filterwarnings("ignore")

import sys, os
import time
import unittest
import threading
import logging
from pkg_resources import iter_entry_points
import mock
import ConfigParser
from ConfigParser import RawConfigParser

sys.path.insert(0,os.path.dirname(__name__))

from janitoo_nosetests import JNTTBase
from janitoo_nosetests.values import JNTTFactory, JNTTFactoryCommon, JNTTFactoryPollCommon, JNTTFactoryConfigCommon

from janitoo.runner import Runner, jnt_parse_args
from janitoo.server import JNTServer
from janitoo.options import JNTOptions

class FactoryConf(object):
    """
    """
    conf_file = 'tests/data/janitoo_audiovideo.conf'

class TestChannelValue(FactoryConf, JNTTFactory, JNTTFactoryCommon):
    """Test the value factory
    """
    entry_name='av_channel'

class TestVolumeValue(FactoryConf, JNTTFactory, JNTTFactoryCommon):
    """Test the value factory
    """
    entry_name='av_volume'

class TestSourceValue(FactoryConf, JNTTFactory, JNTTFactoryCommon):
    """Test the value factory
    """
    entry_name='av_source'

