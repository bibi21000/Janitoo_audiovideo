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
import socket
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

def make_ue46(**kwargs):
    return SamsungUE46(**kwargs)

_mappings = [
    ["p",         "KEY_POWEROFF",      "P",         "Power off"],
    ["KEY_UP",    "KEY_UP",            "Up",        "Up"],
    ["KEY_DOWN",  "KEY_DOWN",          "Down",      "Down"],
    ["KEY_LEFT",  "KEY_LEFT",          "Left",      "Left"],
    ["KEY_RIGHT", "KEY_RIGHT",         "Right",     "Right"],
    ["KEY_PPAGE", "KEY_CHUP",          "Page Up",   "P Up"],
    ["KEY_NPAGE", "KEY_CHDOWN",        "Page Down", "P Down"],
    ["\n",        "KEY_ENTER",         "Enter",     "Enter"],
    ["\x7f",      "KEY_RETURN",        "Backspace", "Return"],
    ["l",         "KEY_CH_LIST",       "L",         "Channel List"],
    ["m",         "KEY_MENU",          "M",         "Menu"],
    ["s",         "KEY_SOURCE",        "S",         "Source"],
    ["g",         "KEY_GUIDE",         "G",         "Guide"],
    ["t",         "KEY_TOOLS",         "T",         "Tools"],
    ["i",         "KEY_INFO",          "I",         "Info"],
    ["z",         "KEY_RED",           "Z",         "A / Red"],
    ["x",         "KEY_GREEN",         "X",         "B / Green"],
    ["c",         "KEY_YELLOW",        "C",         "C / Yellow"],
    ["v",         "KEY_BLUE",          "V",         "D / Blue"],
    ["d",         "KEY_PANNEL_CHDOWN", "D",         "3D"],
    ["+",         "KEY_VOLUP",         "+",         "Volume Up"],
    ["-",         "KEY_VOLDOWN",       "-",         "Volume Down"],
    ["*",         "KEY_MUTE",          "*",         "Mute"],
    ["0",         "KEY_0",             "0",         "0"],
    ["1",         "KEY_1",             "1",         "1"],
    ["2",         "KEY_2",             "2",         "2"],
    ["3",         "KEY_3",             "3",         "3"],
    ["4",         "KEY_4",             "4",         "4"],
    ["5",         "KEY_5",             "5",         "5"],
    ["6",         "KEY_6",             "6",         "6"],
    ["7",         "KEY_7",             "7",         "7"],
    ["8",         "KEY_8",             "8",         "8"],
    ["9",         "KEY_9",             "9",         "9"],
    ["KEY_F(1)",  "KEY_DTV",           "F1",        "TV Source"],
    ["KEY_F(2)",  "KEY_HDMI",          "F2",        "HDMI Source"],
]

class SamsungUE46(JNTComponent):
    """
    """

    def __init__(self, bus=None, addr=None, **kwargs):
        """ Constructor.

        Arguments:
            bus:

            addr:
        """
        JNTComponent.__init__(
            self,
            oid = kwargs.pop('oid','%s.samsung_ue46'%OID),
            bus = bus,
            addr = addr,
            name = kwargs.pop('name',"UE46xxxs Samsung TVs"),
            product_name = kwargs.pop('product_name',"UE46xxxs Samsung TVs"),
            product_type = kwargs.pop('product_type',"TV"),
            **kwargs)
        logger.debug("[%s] - __init__ node uuid:%s", self.__class__.__name__, self.uuid)

        self.tvlock = threading.Lock()

        uuid="ip_ping"
        self.values[uuid] = self.value_factory['ip_ping'](options=self.options, uuid=uuid,
            node_uuid=self.uuid,
            help='Ping the TV',
            label='Ping',
        )
        config_value = self.values[uuid].create_config_value(help='The IP of the TV', label='IP',)
        self.values[config_value.uuid] = config_value
        poll_value = self.values[uuid].create_poll_value(default=60)
        self.values[poll_value.uuid] = poll_value

        uuid="mac_address"
        self.values[uuid] = self.value_factory['config_string'](options=self.options, uuid=uuid,
            node_uuid=self.uuid,
            help='The mac_address of the TV',
            label='MAC address',
        )

        uuid="remote_name"
        self.values[uuid] = self.value_factory['config_string'](options=self.options, uuid=uuid,
            node_uuid=self.uuid,
            help='The name of the remote on the TV',
            label='Remote name',
            default='Janitoo',
        )

        uuid="sleep_delay"
        self.values[uuid] = self.value_factory['config_float'](options=self.options, uuid=uuid,
            node_uuid=self.uuid,
            help='The delay between two commands to the TV',
            label='Delay',
            default=0.05,
        )

        uuid="port_cmd"
        self.values[uuid] = self.value_factory['config_integer'](options=self.options, uuid=uuid,
            node_uuid=self.uuid,
            help='The command port of the TV',
            label='Port_cmd',
            default=55000,
        )

        uuid="port_notif"
        self.values[uuid] = self.value_factory['config_integer'](options=self.options, uuid=uuid,
            node_uuid=self.uuid,
            help='The notification port of the TV',
            label='Port_notif',
            default=52235,
        )

        uuid="channel_change"
        self.values[uuid] = self.value_factory['av_channel'](options=self.options, uuid=uuid,
            node_uuid=self.uuid,
            set_data_cb=self.channel_change,
        )

    def check_heartbeat(self):
        """Check that the component is 'available'

        """
        ret = self.values['ip_ping'].data
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
        return ret

    def channel_change(self, node_uuid, index, data):
        """
        """
        try:
            try:
                remote = SamsungRemote( self.values['ip_ping_config'].data, self.values['port_cmd'].data,
                                        self.values['remote_name'].data, self.values['mac_address'].data)
            except SamsungRemote.AccessDenied:
                logger.error("[%s] - Error: Access to the TV denied!", self.__class__.__name__)
                return
            keys = []
            if data == "up":
                keys.append("KEY_CHUP")
            elif data == "down":
                keys.append("KEY_CHDOWN")
            else:
                for char in data:
                    if char == '0':
                        keys.append('KEY_0')
                    elif char == '1':
                        keys.append('KEY_1')
                    elif char == '2':
                        keys.append('KEY_2')
                    elif char == '3':
                        keys.append('KEY_3')
                    elif char == '4':
                        keys.append('KEY_4')
                    elif char == '5':
                        keys.append('KEY_5')
                    elif char == '6':
                        keys.append('KEY_6')
                    elif char == '7':
                        keys.append('KEY_7')
                    elif char == '8':
                        keys.append('KEY_8')
                    elif char == '9':
                        keys.append('KEY_9')
            with remote:
                for key in keys:
                    remote.control(key)
            with remote:
                remote.control(key)
        except Exception:
            logger.exception('[%s] - Exception when changing channel', self.__class__.__name__)

    def notify_sms(self, rtime=None, receiver=None, receiver_no="0000000000", sender=None, sender_no="0000000000", message="Hello world") :
        logger.debug('notify_sms from  %s', sender_no)
        if rtime is None :
            rtime = time.mktime(time.localtime())
        if receiver is None :
            receiver = receiver_no
        if sender is None :
            sender=sender_no
        body = "<?xml version=\"1.0\" encoding=\"utf-8\"?>" + \
                "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">" + \
                "<s:Body>" + "      <u:AddMessage xmlns:u=\"urn:samsung.com:service:MessageBoxService:1\">" + \
                "         <MessageType>text/xml</MessageType>" + "         <MessageID>MessageId</MessageID>" + \
                "<Message>" + "&lt;Category&gt;SMS&lt;/Category&gt;" + "&lt;DisplayType&gt;Maximum&lt;/DisplayType&gt;" + \
                "&lt;ReceiveTime&gt;" + "&lt;Date&gt;" + time.strftime('%Y-%m-%d', time.localtime(rtime)) + \
                "&lt;/Date&gt;" + "&lt;Time&gt;" + time.strftime('%H:%M:%S', time.localtime(rtime)) + \
                "&lt;/Time&gt;" + "&lt;/ReceiveTime&gt;" + "&lt;Receiver&gt;" + "&lt;Number&gt;" + \
                receiver_no + "&lt;/Number&gt;" + "&lt;Name&gt;" + receiver + \
                "&lt;/Name&gt;" + "&lt;/Receiver&gt;" + "&lt;Sender&gt;" + "&lt;Number&gt;" + \
                sender_no + "&lt;/Number&gt;" + "&lt;Name&gt;" + sender + "&lt;/Name&gt;" + \
                "&lt;/Sender&gt;" + "&lt;Body&gt;" + message + "&lt;/Body&gt;" + "</Message>" + \
                "      </u:AddMessage>" + "   </s:Body>" + "</s:Envelope>";
        self._notify(body)

    def notify_incoming_call(self, rtime=None, receiver=None, receiver_no="0000000000", sender=None, sender_no="0000000000", message="Hello world") :
        logger.debug('notify_incoming_call from  %s', sender_no)
        if rtime is None :
            rtime = time.mktime(time.localtime())
        if receiver is None :
            receiver = receiver_no
        if sender is None :
            sender = sender_no
        body = "<?xml version=\"1.0\" encoding=\"utf-8\"?>" + \
                "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">" + \
                "<s:Body>" + "      <u:AddMessage xmlns:u=\"urn:samsung.com:service:MessageBoxService:1\">" + \
                "         <MessageType>text/xml</MessageType>" + "         <MessageID>MessageId</MessageID>" + \
                "<Message>" + "&lt;Category&gt;Incoming Call&lt;/Category&gt;" + "&lt;DisplayType&gt;Maximum&lt;/DisplayType&gt;" + \
                "&lt;CallTime&gt;" + "&lt;Date&gt;" + time.strftime('%Y-%m-%d', time.localtime(rtime)) + \
                "&lt;/Date&gt;" + "&lt;Time&gt;" + time.strftime('%H:%M:%S', time.localtime(rtime)) + \
                "&lt;/Time&gt;" + "&lt;/CallTime&gt;" + "&lt;Callee&gt;" + "&lt;Number&gt;" + \
                receiver_no + "&lt;/Number&gt;" + "&lt;Name&gt;" + receiver + \
                "&lt;/Name&gt;" + "&lt;/Callee&gt;" + "&lt;Caller&gt;" + "&lt;Number&gt;" + \
                sender_no + "&lt;/Number&gt;" + "&lt;Name&gt;" + sender + "&lt;/Name&gt;" + \
                "&lt;/Caller&gt;" + "&lt;Body&gt;" + message + "&lt;/Body&gt;" + "</Message>" + \
                "      </u:AddMessage>" + "   </s:Body>" + "</s:Envelope>";
        self._notify(body)

    def notify_schedule_reminder(self, starttime=None, endtime=None, owner=None, owner_no="0000000000", message="Hello world") :
        logger.debug('notify_schedule_reminder for  %s', owner_no)
        if starttime is None :
            starttime = time.mktime(time.localtime())
        if endtime is None :
            endtime = time.mktime(time.localtime())
        if owner is None :
            owner = owner_no
        body = "<?xml version=\"1.0\" encoding=\"utf-8\"?>" + \
                "<s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\">" + \
                "<s:Body>" + "      <u:AddMessage xmlns:u=\"urn:samsung.com:service:MessageBoxService:1\">" + \
                "         <MessageType>text/xml</MessageType>" + "         <MessageID>MessageId</MessageID>" + \
                "<Message>" + "&lt;Category&gt;Schedule Reminder&lt;/Category&gt;" + "&lt;DisplayType&gt;Maximum&lt;/DisplayType&gt;" + \
                "&lt;StartTime&gt;" + "&lt;Date&gt;" + time.strftime('%Y-%m-%d', time.localtime(starttime)) + \
                "&lt;/Date&gt;" + "&lt;Time&gt;" + time.strftime('%H:%M:%S', time.localtime(starttime)) + \
                "&lt;/Time&gt;" + "&lt;/StartTime&gt;" + \
                "&lt;EndTime&gt;" + "&lt;Date&gt;" + time.strftime('%Y-%m-%d', time.localtime(endtime)) + \
                "&lt;/Date&gt;" + "&lt;Time&gt;" + time.strftime('%H:%M:%S', time.localtime(endtime)) + \
                "&lt;/Time&gt;" + "&lt;/EndTime&gt;" + \
                "&lt;Owner&gt;" + "&lt;Number&gt;" + \
                owner_no + "&lt;/Number&gt;" + "&lt;Name&gt;" + owner + \
                "&lt;/Name&gt;" + "&lt;/Owner&gt;" + \
                "&lt;Body&gt;" + message + "&lt;/Body&gt;" + "</Message>" + \
                "      </u:AddMessage>" + "   </s:Body>" + "</s:Envelope>";
        self._notify(body)

    def _notify(self,message):
        length = len(message)
        header = "POST /PMR/control/MessageBoxService HTTP/1.0\r\n" + "Content-Type: text/xml; charset=\"utf-8\"\r\n" + \
                "HOST: " + self.values['ip_ping_config'].data + \
                "\r\n" + "Content-Length: " + str(length) + "\r\n" + \
                "SOAPACTION: \"uuid:samsung.com:service:MessageBoxService:1#AddMessage\"\r\n" + "Connection: close\r\n" + "\r\n"
        message = header + message
        try :
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM, 0)
            s.connect((self.id, 52235))
            sent = s.send(message)
            if (sent <= 0):
                logger.error('Error when notify message. No response from %s', self.id)
                s.close()
                return
            recv = s.recv(100000)
            s.close()
        except Exception:
            logger.exeception('Error when notifying %s' % self.id)

    def push(self,key):
        # keys : http://wiki.samygo.tv/index.php5/D-Series_Key_Codes
        try :
            self.tvlock.acquire()
            self.error=0
            new = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            new.connect((self.id, 55000))
            msg = chr(0x64) + chr(0x00) +\
                chr(len(base64.b64encode(self.values['ip_ping_config'].data)))    + chr(0x00) + base64.b64encode(self.values['ip_ping_config'].data) +\
                chr(len(base64.b64encode(self.values['mac_address'].data)))    + chr(0x00) + base64.b64encode(self.values['mac_address'].data) +\
                chr(len(base64.b64encode(self.values['remote_name'].data))) + chr(0x00) + base64.b64encode(self.values['remote_name'].data)
            pkt = chr(0x00) +\
                chr(len(app)) + chr(0x00) + app +\
                chr(len(msg)) + chr(0x00) + msg
            new.send(pkt)
            msg = chr(0x00) + chr(0x00) + chr(0x00) +\
                chr(len(base64.b64encode(key))) + chr(0x00) + base64.b64encode(key)
            pkt = chr(0x00) +\
                chr(len(tvmodel))  + chr(0x00) + tvmodel +\
                chr(len(msg)) + chr(0x00) + msg
            new.send(pkt)
            new.close()
            time.sleep(0.1)
        except Exception:
            logger.exeception('Error when notifying %s' % self.id)
        finally :
            self.tvlock.release()


class SamsungRemote(object):
    class AccessDenied(Exception):
        pass

    class UnhandledResponse(Exception):
        pass

    def __init__(self, host, port, remote_name, mac_address):
        self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connection.connect((host, port))
        ip_source = self.connection.getsockname()[0]

        app = 'janitoo'
        payload = chr(0x64) + chr(0x00) +\
            chr(len(base64.b64encode(ip_source)))    + chr(0x00) + base64.b64encode(ip_source) +\
            chr(len(base64.b64encode(mac_address)))    + chr(0x00) + base64.b64encode(mac_address) +\
            chr(len(base64.b64encode(remote_name))) + chr(0x00) + base64.b64encode(remote_name)
        packet = chr(0x00) +\
            chr(len(app)) + chr(0x00) + app +\
            chr(len(payload)) + chr(0x00) + payload

        logger.debug("Sending handshake.")
        self.connection.send(packet)
        #~ self._read_response(True)

    def __enter__(self):
        return self

    def __exit__(self, type, value, traceback):
        self.close()

    def close(self):
        self.connection.close()

    def control(self, key):
        payload = chr(0x00) + chr(0x00) + chr(0x00) +\
            chr(len(base64.b64encode(key))) + chr(0x00) + base64.b64encode(key)
        packet = chr(0x00) +\
            chr(len('tv'))  + chr(0x00) + 'tv' +\
            chr(len(payload)) + chr(0x00) + payload
        logger.debug("Sending control command.")
        self.connection.send(packet)
        #~ self._read_response(True)
        time.sleep(self._key_interval)

    _key_interval = 0.3

    def _read_response(self, first_time=False):
        header = self.connection.recv(3)
        print header
        tv_name_len = int.from_bytes(header[1:3],
                                     byteorder="little")
        tv_name = self.connection.recv(tv_name_len)
#~ #~
        response_len = int.from_bytes(self.connection.recv(2),
                                      byteorder="little")
        response = self.connection.recv(response_len)
#~ #~
        if response == b"\x64\x00\x01\x00":
            logger.debug("Access granted.")
            return
        elif response == b"\x64\x00\x00\x00":
            raise self.AccessDenied()
        elif response[0:1] == b"\x0a":
            if first_time:
                logger.warning("Waiting for authorization...")
            return self._read_response()
        elif response[0:1] == b"\x65":
            logger.warning("Authorization cancelled.")
            raise self.AccessDenied()
        elif response == b"\x00\x00\x00\x00":
            logger.debug("Control accepted.")
            return
#~ #~
        raise self.UnhandledResponse(response)

    @staticmethod
    def _serialize_string(string, raw = False):
        if not raw:
            string = base64.b64encode(string)

        return bytes([len(string)]) + b"\x00" + string
