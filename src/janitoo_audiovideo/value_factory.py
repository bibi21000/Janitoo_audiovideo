# -*- coding: utf-8 -*-
"""The value

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
__copyright__ = "Copyright © 2013-2014-2015 Sébastien GALLET aka bibi21000"

# Set default logging handler to avoid "No handler found" warnings.
import os
import logging
try:  # Python 2.7+                                   # pragma: no cover
    from logging import NullHandler                   # pragma: no cover
except ImportError:                                   # pragma: no cover
    class NullHandler(logging.Handler):               # pragma: no cover
        """NullHandler logger for python 2.6"""       # pragma: no cover
        def emit(self, record):                       # pragma: no cover
            pass                                      # pragma: no cover
logger = logging.getLogger( __name__ )

from janitoo.classes import GENRE_DESC, VALUE_DESC
from janitoo.utils import json_dumps
from janitoo.value import JNTValue
from janitoo.value_factory import JNTValueFactoryEntry

##############################################################
#Check that we are in sync with the official command classes
#Must be implemented for non-regression
from janitoo.classes import COMMAND_DESC

COMMAND_CONFIGURATION = 0x0070
COMMAND_AV_CHANNEL = 0x2100
COMMAND_AV_VOLUME = 0x2101
COMMAND_AV_SOURCE = 0x2102

assert(COMMAND_DESC[COMMAND_CONFIGURATION] == 'COMMAND_CONFIGURATION')
assert(COMMAND_DESC[COMMAND_AV_SOURCE] == 'COMMAND_AV_SOURCE')
assert(COMMAND_DESC[COMMAND_AV_VOLUME] == 'COMMAND_AV_VOLUME')
assert(COMMAND_DESC[COMMAND_AV_CHANNEL] == 'COMMAND_AV_CHANNEL')
##############################################################

def make_av_channel(**kwargs):
    return JNTValueChannel(**kwargs)

def make_av_volume(**kwargs):
    return JNTValueVolume(**kwargs)

def make_av_source(**kwargs):
    return JNTValueSource(**kwargs)

class JNTValueChannel(JNTValueFactoryEntry):
    """
    """
    def __init__(self, entry_name="av_channel", **kwargs):
        help = kwargs.pop('help', 'Change the channel to : up, down or #channel')
        label = kwargs.pop('label', 'Channel')
        index = kwargs.pop('index', 0)
        cmd_class = kwargs.pop('cmd_class', COMMAND_AV_CHANNEL)
        JNTValueFactoryEntry.__init__(self, entry_name=entry_name, help=help, label=label,
            get_data_cb=get_data_cb, set_data_cb=None,
            index=index, cmd_class=cmd_class, genre=0x02, type=0x08, is_writeonly=True, **kwargs)

class JNTValueVolume(JNTValueFactoryEntry):
    """
    """
    def __init__(self, entry_name="av_volume", **kwargs):
        help = kwargs.pop('help', 'Change the volume to : up, down or #volume')
        label = kwargs.pop('label', 'Volume')
        index = kwargs.pop('index', 0)
        cmd_class = kwargs.pop('cmd_class', COMMAND_AV_VOLUME)
        JNTValueFactoryEntry.__init__(self, entry_name=entry_name, help=help, label=label,
            get_data_cb=get_data_cb, set_data_cb=None,
            index=index, cmd_class=cmd_class, genre=0x02, type=0x08, is_writeonly=True, **kwargs)

class JNTValueSource(JNTValueFactoryEntry):
    """
    """
    def __init__(self, entry_name="av_source", **kwargs):
        help = kwargs.pop('help', 'Change the source')
        label = kwargs.pop('label', 'Source')
        index = kwargs.pop('index', 0)
        cmd_class = kwargs.pop('cmd_class', COMMAND_AV_SOURCE)
        JNTValueFactoryEntry.__init__(self, entry_name=entry_name, help=help, label=label,
            get_data_cb=get_data_cb, set_data_cb=None,
            index=index, cmd_class=cmd_class, genre=0x02, type=0x08, is_writeonly=True, **kwargs)

