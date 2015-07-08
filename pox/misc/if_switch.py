# Copyright 2012 James McCauley
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at:
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
This component is for use with the OpenFlow tutorial.

It acts as a simple hub, but can be modified to act like an L2
learning switch.

It's roughly similar to the one Brandon Heller did for NOX.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of

from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.arp import arp
from pox.lib.addresses import IPAddr, EthAddr
from pox.lib.util import str_to_bool, dpid_to_str

import threading
import time
import commands

log = core.getLogger()



class Tutorial (object):
  def __init__ (self, connection):
    # Keep track of the connection to the switch so that we can
    # send it messages!
    self.connection = connection

    # This binds our PacketIn event listener
    connection.addListeners(self)

    # Event handler for flow stats message
    core.openflow.addListenerByName("FlowStatsReceived", self.handle_flow_stats)

    # Use this table to keep track of which ethernet address is on
    # which switch port (keys are MACs, values are ports).
    self.mac_to_port = {}

    # initialize thread for flow_stats_request
    # t = threading.Thread(target = self.flow_stats_polling)
    # t.start()

    self.start_time = time.time();


  def resend_packet (self, packet_in, out_port):
    msg = of.ofp_packet_out()
    msg.data = packet_in

    # Add an action to send to the specified port
    action = of.ofp_action_output(port = out_port)
    msg.actions.append(action)

    # Send message to switch
    self.connection.send(msg)

  #
  # Ethernet Frame Member
  # pox/lib/packet/ethernet.py
  #
  # dst       : Destination MAC Address
  # src       : Source MAC Address
  # type      : Ether Type
  #                         IP_TYPE   = 0x0800
  #                         ARP_TYPE  = 0x0806
  #                         RARP_TYPE = 0x8035
  #                         VLAN_TYPE = 0x8100
  #                         MPLS_TYPE = 0x8847
  #                         INVALID_TYPE = 0xffff
  # hdr_len   : Ethernet Header Length
  # payload   : Ethernet Frame Payload
  #

  #
  # IP Packet Member
  # pox/lib/packet/ipv4.py
  #
  # v         : IP Version
  # hl        : HP Header Length
  # tos       : Type of Service
  # iplen     : Total Length
  # id        : Identification
  # flags     : Flags
  # frag      : Fragment Offset
  # ttl       : Time to Live
  # protocol  : Protocol
  #                       IPv4  = 4
  #                       ICMP  = 1
  #                       TCP   = 6
  #                       UDP   = 17
  #                       IGMP  = 2
  # csum      : Header Checksum
  # srcip     : Source Address
  # dstip     : Destination Address
  #

  #
  # Match Structure
  #
  # in_port       Switch port number the packet arrived on
  # dl_src        Ethernet source address
  # dl_dst        Ethernet destination address
  # dl_vlan       VLAN ID
  # dl_valn_pcp   VLAN priority
  # dl_type       Ethertype
  # nw_tos        IP TOS/DS bits
  # nw_proto      IP protocol
  # nw_src        IP source address
  # nw_dst        IP destination address
  # tp_src        TCP/UDP source port
  # tp_dst        TCP/UDP destination port
  #
  # -- create match object and set paramater --
  #
  # my_match = of.ofp_match(in_port=5, dl_dst=EthAddr("01:02:03:04:05:06"))
  #
  # .. or ..
  #
  # my_match = of.ofp_match()
  # my_match.in_port = 5
  # my_match.dl_dst = EthAddr("01:02:03:04:05:06")
  #
  # -- Defining a match from an existing packet --
  #
  # my_match = ofp_match.from_packet(packet, in_port)
  #
  def act_like_switch (self, packet, packet_in):

    self.mac_to_port[packet.src] = packet_in.in_port

    if packet.dst in self.mac_to_port:

      log.debug("Installing flow...")

      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match()
      msg.match.dl_dst = packet.dst
      msg.actions.append(of.ofp_action_output(\
                                port = self.mac_to_port[packet.dst]))

      self.connection.send(msg)

      msg = of.ofp_packet_out()
      msg.data = packet_in
      msg.actions.append(of.ofp_action_output(\
                                port = self.mac_to_port[packet.dst]))
      self.connection.send(msg)

    else:
      self.resend_packet(packet_in, of.OFPP_ALL)

  def act_like_ifswitch (self, eth_packet, packet_in):
    # mac address table update
    self.mac_to_port[eth_packet.src] = packet_in.in_port

    # IP protocol
    if (eth_packet.type == ethernet.IP_TYPE) :
      ip_packet = eth_packet.payload

      # Ingress Filtering
      # allow 10.0.0.0/24
      if (ip_packet.srcip.inNetwork("10.0.0.0", 24) == False) :
        # log.debug("drop")

        # make flow rule and send
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match()
        msg.match.dl_type = eth_packet.type
        msg.match.in_port = packet_in.in_port
        msg.match.nw_src = ip_packet.srcip
        self.connection.send(msg)
        return;

      # matching EtherType, DstMAC, SrcIP 
      elif (eth_packet.dst in self.mac_to_port) :
        log.debug("Installing flow_mod for IP ...")

        # make flow rule and send
        action = of.ofp_action_output(
                          port = self.mac_to_port[eth_packet.dst])
        msg = of.ofp_flow_mod()
        msg.match = of.ofp_match()
        msg.match.in_port = packet_in.in_port
        msg.match.dl_type = eth_packet.type
        msg.match.dl_dst = eth_packet.dst
        msg.match.nw_src = ip_packet.srcip
        msg.actions.append(action)
        self.connection.send(msg)

        # packet out
        msg = of.ofp_packet_out()
        msg.data = packet_in
        msg.actions.append(action)
        self.connection.send(msg)
        return;

    # not IP protocol eg. ARP
    # matching EtherType, DstMac
    elif (eth_packet.dst in self.mac_to_port) :
      log.debug("Installing flow_mod for ARP ...")

      # make flow rule and send
      action = of.ofp_action_output(
                        port = self.mac_to_port[eth_packet.dst])
      msg = of.ofp_flow_mod()
      msg.match = of.ofp_match()
      msg.match.dl_type = eth_packet.type
      msg.match.dl_dst = eth_packet.dst
      msg.actions.append(action)
      self.connection.send(msg)

      # packet out
      msg = of.ofp_packet_out()
      msg.data = packet_in
      msg.actions.append(action)
      self.connection.send(msg)
      return;

    # flooding : no DstMAC info in table
    self.resend_packet(packet_in, of.OFPP_ALL)

  def flow_stats_polling (self):
    """
    Send flow_stats_request every 1sec.
    """

    msg = of.ofp_stats_request(body = of.ofp_flow_stats_request())
    self.connection.send(msg)
    
    # Start next thread after 1sec.
    t = threading.Timer(1, self.flow_stats_polling)
    t.start()

  def _handle_PacketIn (self, event):
    """
    Handles packet in messages from the switch.
    """

    packet = event.parsed # This is the parsed packet data.
    if not packet.parsed:
      log.warning("Ignoring incomplete packet")
      return

    packet_in = event.ofp # The actual ofp_packet_in message.

    # simple l2 learning switch
    # self.act_like_switch(packet, packet_in)

    # l2 learning switch with Ingress Filter
    self.act_like_ifswitch(packet, packet_in)

  def handle_flow_stats (self, event):
    """
    Handles flow stats messages from the switch.
    Check flow table statistics and count web flows.
    """
    web_bytes = 0
    web_flows = 0
    for flow in event.stats:
      if f.match.tp_dst == 80 or f.match.tp_src == 80:
        web_bytes += f.byte_count
        web_flows += 1

def launch ():
  """
  Starts the component
  """
  def start_switch (event):
    log.debug("Controlling %s" % (event.connection,))
    Tutorial(event.connection)
  core.openflow.addListenerByName("ConnectionUp", start_switch)
