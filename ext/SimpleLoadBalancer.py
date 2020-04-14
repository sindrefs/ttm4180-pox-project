from pox.core import core
from pox.openflow import *
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.addresses import EthAddr, IPAddr

log = core.getLogger()
import time
import random
import pox.log.color

IDLE_TIMEOUT = 10
LOADBALANCER_MAC = EthAddr("00:00:00:00:00:FE")
ETHERNET_BROADCAST_ADDRESS = EthAddr("ff:ff:ff:ff:ff:ff")


class SimpleLoadBalancer(object):

    def __init__(self, service_ip, server_ips=[]):
        core.openflow.addListeners(self)
        self.SERVERS = {}  # IPAddr(SERVER_IP)]={'server_mac':EthAddr(SERVER_MAC),'port': PORT_TO_SERVER}
        self.CLIENTS = {}
        self.LOADBALANCER_MAP = {}  # Mapping between clients and servers
        self.LOADBALANCER_IP = service_ip
        self.SERVER_IPS = server_ips
        self.ROBIN_COUNT = 0

    def _handle_ConnectionUp(self, event):
        self.connection = event.connection
        log.debug("FUNCTION: _handle_ConnectionUp")

        # TODO_M: Send ARP Requests to learn the MAC address of all Backend Servers.

        # START ANSWER
        for server_ip in self.SERVER_IPS:
            self.send_arp_request(self.connection, server_ip)
        # END
        log.debug("Sent ARP Requests to all servers")

    def round_robin(self):
        log.debug("FUNCTION: round_robin")

        # TODO_M: Implement logic to choose the next server according to
        #         the Round Robin scheduling algorithm

        # START ANSWER
        server = self.SERVER_IPS[self.ROBIN_COUNT] # Server ip ONLY
        # OLD implementation:  server = self.SERVERS[server_ip]
        self.ROBIN_COUNT = (self.ROBIN_COUNT + 1) % len(self.SERVER_IPS)
        # END

        log.info("Round robin selected: %s" % server)
        return server

    def update_lb_mapping(self, client_ip):
        log.debug("FUNCTION: update_lb_mapping")
        if client_ip in self.CLIENTS.keys():
            if client_ip not in self.LOADBALANCER_MAP.keys():
                selected_server = self.round_robin()  # Select the server which will handle the request

                self.LOADBALANCER_MAP[client_ip] = selected_server

    def send_arp_reply(self, packet, connection, outport):
        log.debug("FUNCTION: send_arp_reply")

        arp_rep = arp()  # Create an ARP reply
        arp_rep.hwtype = arp_rep.HW_TYPE_ETHERNET
        arp_rep.prototype = arp_rep.PROTO_TYPE_IP
        arp_rep.hwlen = 6
        arp_rep.protolen = arp_rep.protolen
        arp_rep.opcode = arp.REPLY  # Set the ARP TYPE to REPLY

        arp_rep.hwdst = packet.src  # Set MAC destination
        arp_rep.hwsrc = LOADBALANCER_MAC  # Set MAC source

        # Reverse the src, dest to have an answer
        arp_rep.protosrc = self.LOADBALANCER_IP  # Set IP source
        arp_rep.protodst = packet.payload.protosrc  # Set IP destination

        # TODO: Needed to pass in arp_rep as an argument or not to ethernet() (?)
        eth = ethernet()  # Create an ethernet frame and set the arp_rep as it's payload.
        eth.type = ethernet.ARP_TYPE  # Set packet Type
        eth.dst = packet.src  # Set destination of the Ethernet Frame
        eth.src = LOADBALANCER_MAC  # Set source of the Ethernet Frame
        eth.set_payload(arp_rep)

        msg = of.ofp_packet_out()  # create the necessary Openflow Message to make the switch send the ARP Reply
        msg.data = eth.pack()

        # TODO: Change to outport (test)
        msg.actions.append(of.ofp_action_output(
            port=of.OFPP_IN_PORT))  # Append the output port which the packet should be forwarded to.

        msg.in_port = outport
        connection.send(msg)

    def send_arp_request(self, connection, ip):
        # Difficulties? https://en.wikipedia.org/wiki/Address_Resolution_Protocol#Example

        log.debug("FUNCTION: send_arp_request")

        arp_req = arp()  # Create an instance of an ARP REQUEST PACKET
        arp_req.hwtype = arp_req.HW_TYPE_ETHERNET
        arp_req.prototype = arp_req.PROTO_TYPE_IP
        arp_req.hwlen = 6
        arp_req.protolen = arp_req.protolen
        arp_req.opcode = arp.REQUEST  # Set the opcode
        arp_req.protodst = ip  # IP the load balancer is looking for
        arp_req.hwsrc = LOADBALANCER_MAC  # Set the MAC source of the ARP REQUEST
        arp_req.hwdst = ETHERNET_BROADCAST_ADDRESS  # Set the MAC address in such a way that the packet is marked as a Broadcast
        arp_req.protosrc = self.LOADBALANCER_IP  # Set the IP source of the ARP REQUEST

        # TODO: Needed to pass in arp_req as an argument or not to ethernet() (?)
        eth = ethernet()  # Create an ethernet frame and set the arp_req as it's payload.
        eth.type = ethernet.ARP_TYPE  # Set packet Typee
        eth.dst = ETHERNET_BROADCAST_ADDRESS  # Set the MAC address in such a way that the packet is marked as a Broadcast
        eth.set_payload(arp_req)

        msg = of.ofp_packet_out()  # Create the necessary Openflow Message to make the switch send the ARP Request
        msg.data = eth.pack()
        msg.actions.append(of.ofp_action_nw_addr(of.OFPAT_SET_NW_DST, ip))
        #NEW: msg.actions.append(of.ofp_action_nw_addr(of.ofp_port_rev_map.OFPAT_SET_NW_DST, ip))
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))  # Append an action to the message
        # which makes the switch flood the packet out
        #NEW: msg.actions.append(of.ofp_action_output(port=of.ofp_port_rev_map.OFPP_FLOOD))  # Append an action to the
        # message which makes the switch flood the packet out

        connection.send(msg)

    def install_flow_rule_client_to_server(self, event, connection, outport, client_ip, server_ip):
        log.debug("FUNCTION: install_flow_rule_client_to_server")
        self.install_flow_rule_server_to_client(connection, event.port, server_ip, client_ip)

        msg = of.ofp_flow_mod()  # Create an instance of the type of Openflow packet you need to install flow table
        # entries

        msg.idle_timeout = IDLE_TIMEOUT

        msg.match.dl_type = ethernet.IP_TYPE
        # TODO: Match nw_dst to load balancer ip or actual server ip???
        msg.match = of.ofp_match(nw_src=client_ip, nw_dst=self.LOADBALANCER_IP)  # MATCH on destination and source IP

        # SET dl_addr source and destination addresses
        msg.actions.append(of.ofp_action_dl_addr.set_dst(dl_addr=self.SERVERS[server_ip]['server_mac']))
        msg.actions.append(of.ofp_action_dl_addr.set_src(dl_addr=self.CLIENTS[client_ip]['client_mac']))

        # SET nw_addr source and destination addresses
        msg.actions.append(of.ofp_action_nw_addr.set_dst(nw_addr=server_ip))
        msg.actions.append(of.ofp_action_nw_addr.set_src(nw_addr=client_ip))

        # Set Port to send matching packets out
        msg.actions.append(of.ofp_action_output(port=self.SERVERS[server_ip]['port']))

        self.connection.send(msg)
        log.info("Installed flow rule: %s -> %s" % (client_ip, server_ip))

    def install_flow_rule_server_to_client(self, connection, outport, server_ip, client_ip):
        log.debug("FUNCTION: install_flow_rule_server_to_client")

        msg = of.ofp_flow_mod()  # Create an instance of the type of Openflow packet you need to install flow table
        # entries
        msg.idle_timeout = IDLE_TIMEOUT

        msg.match.dl_type = ethernet.IP_TYPE

        msg.match = of.ofp_match(nw_src=server_ip, nw_dst=client_ip)  # MATCH on destination and source IP

        # SET dl_addr source and destination addresses
        msg.actions.append(of.ofp_action_dl_addr.set_dst(dl_addr=self.CLIENTS[client_ip]['client_mac']))
        msg.actions.append(of.ofp_action_dl_addr.set_src(dl_addr=LOADBALANCER_MAC))

        # SET nw_addr source and destination addresses
        msg.actions.append(of.ofp_action_nw_addr.set_dst(nw_addr=client_ip))
        msg.actions.append(of.ofp_action_nw_addr.set_src(nw_addr=self.LOADBALANCER_IP))

        # Set Port to send matching packets out
        msg.actions.append(of.ofp_action_output(port=self.CLIENTS[client_ip]['port']))

        self.connection.send(msg)
        log.info("Installed flow rule: %s -> %s" % (server_ip, client_ip))

    def _handle_PacketIn(self, event):
        log.debug("FUNCTION: _handle_PacketIn")
        packet = event.parsed
        connection = event.connection
        inport = event.port
        if packet.type == packet.LLDP_TYPE or packet.type == packet.IPV6_TYPE:
            log.info("Received LLDP or IPv6 Packet...")

        elif packet.type == packet.ARP_TYPE:  # Handle ARP Packets
            log.debug("Received ARP Packet")
            response = packet.payload
            if packet.payload.opcode == arp.REPLY:  # Handle ARP replies
                log.debug("ARP REPLY Received")
                if response.protosrc not in self.SERVERS.keys():
                    self.SERVERS[IPAddr(response.protosrc)] = {"server_mac": EthAddr(response.hwsrc), "port": inport}
                    log.info(self.SERVERS)#
                    # Add Servers MAC and port to SERVERS dict

            elif packet.payload.opcode == arp.REQUEST:  # Handle ARP requests
                log.debug("ARP REQUEST Received")
                if response.protosrc not in self.SERVERS.keys() and response.protosrc not in self.CLIENTS.keys():
                    self.CLIENTS[response.protosrc] = {'client_mac': EthAddr(packet.payload.hwsrc),
                                                       'port': inport}  # insert client's ip  mac and port to a
                    # forwarding table

                if response.protosrc in self.CLIENTS.keys() and response.protodst == self.LOADBALANCER_IP:
                    log.info("Client %s sent ARP req to LB %s" % (response.protosrc, response.protodst))
                    # Load Balancer intercepts ARP Client -> Server
                    self.send_arp_reply(packet, connection, inport)  # Send ARP Reply to the client, include the
                    # event.connection object

                elif response.protosrc in self.SERVERS.keys() and response.protodst in self.CLIENTS.keys():
                    log.info("Server %s sent ARP req to client" % response.protosrc)
                    # Load Balancer intercepts ARP from Client <- Server
                    self.send_arp_reply(packet, connection,
                                        inport)  # Send ARP Reply to the Server, include the event.connection object
                else:
                    log.info("Invalid ARP request")

        elif packet.type == packet.IP_TYPE:  # Handle IP Packets
            log.debug("Received IP Packet from %s" % packet.next.srcip)
            # Handle Requests from Clients to Servers
            # Install flow rule Client -> Server
            if packet.next.dstip == self.LOADBALANCER_IP and not packet.next.srcip in self.SERVERS.keys():  # Check if
                # the packet is destined for the LB and the source is not a server :

                self.update_lb_mapping(packet.next.srcip)
                client_ip = packet.payload.srcip  # Get client IP from the packet
                server_ip = self.LOADBALANCER_MAP.get(packet.next.srcip)
                log.info("SERVER IP " + str(server_ip) + "\n")
                outport = self.SERVERS[server_ip]['port']  # Get Port of Server

                self.install_flow_rule_client_to_server(event, connection, outport, client_ip, server_ip)

                # Either use the code below to create a new Ethernet packet, or use Buffer_Id
                eth = ethernet()
                eth.type = eth.IP_TYPE  # Set the correct Ethernet TYPE, to send an IP Packet
                eth.dst = self.SERVERS[server_ip]['server_mac']  # Set the MAC destination
                eth.src = LOADBALANCER_MAC  # Set the MAC source
                eth.set_payload(packet.next)

                # Send the first packet (which was sent to the controller from the switch)
                # to the chosen server, so there is no packetloss
                msg = of.ofp_packet_out()  # Create an instance of a message which can be used to instruct the switch to send a packet
                msg.data = eth.pack()
                msg.in_port = inport  # Set the correct in_port

                # Add an action which sets the MAC source to the LB's MAC
                msg.actions.append(of.ofp_action_dl_addr.set_src(dl_addr=LOADBALANCER_MAC))

                # Add an action which sets the MAC destination to the intended destination...
                msg.actions.append(of.ofp_action_dl_addr.set_dst(dl_addr=self.SERVERS[server_ip]['server_mac']))

                # Add an action which sets the IP source
                msg.actions.append(of.ofp_action_nw_addr.set_src(nw_addr=client_ip))

                # Add an action which sets the IP destination
                msg.actions.append(of.ofp_action_nw_addr.set_dst(nw_addr=server_ip))

                # Add an action which sets the Outport
                msg.actions.append(of.ofp_action_output(port=outport))

                connection.send(msg)

            # Handle traffic from Server to Client
            # Install flow rule Client <- Server
            elif packet.next.dstip in self.CLIENTS.keys():  # server to client
                log.info("Installing flow rule from Server -> Client")
                if packet.next.srcip in self.SERVERS.keys():
                    server_ip = packet.payload.dstip  # Get the source IP from the IP Packet

                    client_ip = self.LOADBALANCER_MAP.keys()[
                        list(self.LOADBALANCER_MAP.values()).index(packet.next.srcip)]
                    outport = int(self.CLIENTS[client_ip].get('port'))
                    self.install_flow_rule_server_to_client(connection, outport, server_ip, client_ip)

                    # Either use the code below to create a new Ethernet packet, or use Buffer_Id
                    eth = ethernet()
                    eth.type = eth.IP_TYPE  # Set the correct Ethernet TYPE, to send an IP Packet
                    eth.dst = self.CLIENTS[client_ip]['client_mac']  # Set the MAC destination
                    eth.src = LOADBALANCER_MAC  # Set the MAC source
                    eth.set_payload(packet.next)

                    # Send the first packet (which was sent to the controller from the switch)
                    # to the chosen server, so there is no packetloss
                    msg = of.ofp_packet_out()  # Create an instance of a message which can be used to instruct the
                    # switch to send a packet
                    msg.data = eth.pack()
                    msg.in_port = inport  # Set the correct in_port

                    #  Add an action which sets the MAC source to the LB's MAC
                    msg.actions.append(of.ofp_action_dl_addr.set_src(dl_addr=LOADBALANCER_MAC))

                    #  Add an action which sets the MAC destination to the intended destination...
                    msg.actions.append(of.ofp_action_dl_addr.set_dst(dl_addr=self.CLIENTS[client_ip]['client_mac']))

                    #  Add an action which sets the IP source
                    msg.actions.append(of.ofp_action_nw_addr.set_src(nw_addr=self.LOADBALANCER_IP))

                    #  Add an action which sets the IP destination
                    msg.actions.append(of.ofp_action_nw_addr.set_dst(nw_addr=client_ip))

                    #  Add an action which sets the Outport
                    msg.actions.append(of.ofp_action_output(port=outport))

                    self.connection.send(msg)


        else:
            log.info("Unknown Packet type: %s" % packet.type)
            return
        return


def launch(loadbalancer, servers):
    # Color-coding and pretty-printing the log output
    pox.log.color.launch()
    pox.log.launch(format="[@@@bold@@@level%(name)-23s@@@reset] " +
                          "@@@bold%(message)s@@@normal")
    log.info(
        "Loading Simple Load Balancer module:\n\n-----------------------------------CONFIG----------------------------------\n")
    server_ips = servers.replace(",", " ").split()
    server_ips = [IPAddr(x) for x in server_ips]
    loadbalancer_ip = IPAddr(loadbalancer)
    log.info("Loadbalancer IP: %s" % loadbalancer_ip)
    log.info(
        "Backend Server IPs: %s\n\n---------------------------------------------------------------------------\n\n" % ', '.join(
            str(ip) for ip in server_ips))
    core.registerNew(SimpleLoadBalancer, loadbalancer_ip, server_ips)
