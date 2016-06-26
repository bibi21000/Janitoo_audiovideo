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

import time
import threading
from subprocess import Popen, PIPE
import base64
import re
import requests
from janitoo.utils import HADD
from janitoo.component import JNTComponent

##############################################################
#Check that we are in sync with the official command classes
#Must be implemented for non-regression
from janitoo.classes import COMMAND_DESC

COMMAND_DISPLAY = 0x0061
COMMAND_AV_CHANNEL = 0x2100
COMMAND_AV_VOLUME = 0x2101
COMMAND_NOTIFY = 0x3010

assert(COMMAND_DESC[COMMAND_DISPLAY] == 'COMMAND_DISPLAY')
assert(COMMAND_DESC[COMMAND_AV_CHANNEL] == 'COMMAND_AV_CHANNEL')
assert(COMMAND_DESC[COMMAND_AV_VOLUME] == 'COMMAND_AV_VOLUME')
assert(COMMAND_DESC[COMMAND_NOTIFY] == 'COMMAND_NOTIFY')
##############################################################

from janitoo_audiovideo import OID

def make_livebox(**kwargs):
    return Livebox(**kwargs)

class Livebox(JNTComponent):
    """
    """

    def __init__(self, bus=None, addr=None, **kwargs):
        """ Constructor.

        From https://lafibre.info/orange-les-news/piloter-le-decodeur-depuis-son-pc/

        Arguments:
            bus:

            addr:
        """
        JNTComponent.__init__(
            self,
            oid = kwargs.pop('oid','%s.livebox'%OID),
            bus = bus,
            addr = addr,
            name = kwargs.pop('name',"Livebox TV"),
            product_name = kwargs.pop('product_name',"Livebox TV"),
            product_type = kwargs.pop('product_type',"TV box"),
            **kwargs)
        logger.debug("[%s] - __init__ node uuid:%s", self.__class__.__name__, self.uuid)

        self.tvlock = threading.Lock()

        uuid="ip_ping"
        self.values[uuid] = self.value_factory['ip_ping'](options=self.options, uuid=uuid,
            node_uuid=self.uuid,
            help='Ping the TV box',
            label='Ping',
        )
        config_value = self.values[uuid].create_config_value(help='The IP of the TV box', label='IP',)
        self.values[config_value.uuid] = config_value
        poll_value = self.values[uuid].create_poll_value(default=60)
        self.values[poll_value.uuid] = poll_value

        uuid="mac_address"
        self.values[uuid] = self.value_factory['config_string'](options=self.options, uuid=uuid,
            node_uuid=self.uuid,
            help='The mac_address of the TV',
            label='MAC address',
        )

        uuid="sleep_delay"
        self.values[uuid] = self.value_factory['config_float'](options=self.options, uuid=uuid,
            node_uuid=self.uuid,
            help='The delay between two commands to the TV',
            label='Delay',
            default=0.02,
        )

        uuid="port_cmd"
        self.values[uuid] = self.value_factory['config_integer'](options=self.options, uuid=uuid,
            node_uuid=self.uuid,
            help='The command port of the TV',
            label='Port_cmd',
            default=8080,
        )

        uuid="channel_change"
        self.values[uuid] = self.value_factory['av_channel'](options=self.options, uuid=uuid,
            node_uuid=self.uuid,
            set_data_cb=self.channel_change,
        )

        uuid="volume_change"
        self.values[uuid] = self.value_factory['av_volume'](options=self.options, uuid=uuid,
            node_uuid=self.uuid,
            set_data_cb=self.volume_change,
        )

        uuid = "request_timeout"
        self.values[uuid] = self.value_factory['config_float'](options=self.options, uuid=uuid,
            node_uuid=self.uuid,
            help='The timeout for requests',
            label='req_timeout',
            default=5,
        )

    def get_macc(self):
        """Check that the component is 'available'

        """
        if self.values['mac_address'].data is None or self.values['mac_address'].data == "":
            try:
                if self.values['ip_ping_config'].data is not None:
                    pid = Popen(["/usr/sbin/arp", "-n", '%s'%self.values['ip_ping_config'].data], stdout=PIPE)
                    s = pid.communicate()[0]
                    remac = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", s)
                    if remac is not None:
                        macaddress = remac.groups()[0]
                        self.values['mac_address'].data = macaddress
                logger.warning("[%s] - Can't retrieve mac address of %s", self.__class__.__name__, self.values['ip_ping_config'].data)
            except Exception:
                logger.exception('[%s] - Exception when retrieving mac address of %s', self.__class__.__name__, self.values['ip_ping_config'].data)

    def check_heartbeat(self):
        """Check that the component is 'available'

        """
        ret = self.values['ip_ping'].data
        return ret

    def channel_change(self, node_uuid, index, data):
        """
        """
        try:
            self.get_macc()
            keys = []
            if data == "up":
                keys.append(402)
            elif data == "down":
                keys.append(403)
            else:
                for char in data:
                    if char == '0':
                        keys.append(512)
                    elif char == '1':
                        keys.append(513)
                    elif char == '2':
                        keys.append(514)
                    elif char == '3':
                        keys.append(515)
                    elif char == '4':
                        keys.append(516)
                    elif char == '5':
                        keys.append(517)
                    elif char == '6':
                        keys.append(518)
                    elif char == '7':
                        keys.append(519)
                    elif char == '8':
                        keys.append(520)
                    elif char == '9':
                        keys.append(521)
            for key in keys:
                logger.info('http://%s:%s/remoteControl/cmd?operation=01&key=%s&mode=0'%(self.values['ip_ping_config'].data, self.values['port_cmd'].data, key))
                r = requests.get('http://%s:%s/remoteControl/cmd?operation=01&key=%s&mode=0'%(self.values['ip_ping_config'].data, self.values['port_cmd'].data, key), timeout=self.values['request_timeout'].data)
                time.sleep(self.values['sleep_delay'].data)

        except Exception:
            logger.exception('[%s] - Exception when changing channel', self.__class__.__name__)

    def volume_change(self, node_uuid, index, data):
        """
        """
        try:
            self.get_macc()
            keys = []
            if data == "up":
                keys.append(115)
            elif data == "down":
                keys.append(114)
            elif data == "mute":
                keys.append(113)
            for key in keys:
                logger.info('http://%s:%s/remoteControl/cmd?operation=01&key=%s&mode=0'%(self.values['ip_ping_config'].data, self.values['port_cmd'].data, key))
                r = requests.get('http://%s:%s/remoteControl/cmd?operation=01&key=%s&mode=0'%(self.values['ip_ping_config'].data, self.values['port_cmd'].data, key), timeout=self.values['request_timeout'].data)
                time.sleep(self.values['sleep_delay'].data)

        except Exception:
            logger.exception('[%s] - Exception when changing channel', self.__class__.__name__)
