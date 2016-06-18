# -*- coding: utf-8 -*-
"""The Samsung Janitoo helper

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

# Set default logging handler to avoid "No handler found" warnings.
import logging
logger = logging.getLogger(__name__)
import os, sys
import threading
import time
from datetime import datetime, timedelta
from subprocess import Popen, PIPE
import base64
import re
import socket
from janitoo.options import get_option_autostart
from janitoo.utils import HADD, HADD_SEP, json_dumps, json_loads
from janitoo.thread import JNTBusThread
from janitoo.bus import JNTBus
from janitoo_factory.threads.http import DocumentationResourceComponent

from janitoo_audiovideo import OID

def make_thread(options, force=False):
    if get_option_autostart(options, OID) == True or force:
        return AudioVideoThread(options)
    else:
        return None

def make_doc(**kwargs):
    return DocumentationAudiovideo(**kwargs)

class AudioVideoThread(JNTBusThread):
    """The AudioVideoThread thread

    """
    def init_bus(self):
        """Build the bus
        """
        self.section = OID
        self.bus = JNTBus(options=self.options, oid=self.section, product_name="AudioVideo controller")

class DocumentationAudiovideo(DocumentationResourceComponent):
    """ A resource ie /rrd """

    def __init__(self, path='audiovideo', bus=None, addr=None, **kwargs):
        """
        """
        DocumentationResourceComponent.__init__(self, path=path, oid='http.doc_audiovideo', bus=bus, addr=addr, **kwargs)
        self.values['key'].instances.update({
            0:{'config':'controller.audiovideo.install', 'doc':'install.md'},
            1:{'config':'controller.audiovideo.use', 'doc':'use.md'},
        })
        self.values['resource'].instances = self.values['key'].instances

    def get_package_name(self):
        """Return the name of the package. Needed to publish static files

        **MUST** be copy paste in every extension that publish statics files
        """
        return __package__

    def get_key(self, node_uuid, index):
        """
        """
        if index in self.values['key'].instances:
            return self.values['key'].instances[index]['config']

    def get_resource(self, node_uuid, index):
        """
        """
        #~ print "============ self.configs_instances", self.configs_instances
        if index in self.values['key'].instances:
            return self._bus.get_resource_path()% ( '%s/%s'%(self.path, self.values['key'].instances[index]['doc']))
