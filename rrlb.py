from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types

# ADDED:
from ryu.lib.packet import arp, ipv4


class RoundRobinLoadBalancer(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(RoundRobinLoadBalancer, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

        # ADDED: VIP definition
        self.VIP_IP = "10.0.0.100"
        self.VIP_MAC = "AA:BB:CC:DD:EE:FF"

        # ADDED: three backend servers for round robin
        self.SERVERS = [
            ("10.0.0.1", "00:00:00:00:00:01"), 
            ("10.0.0.2", "00:00:00:00:00:02"),
            ("10.0.0.3", "00:00:00:00:00:03")
        ]
        self.rr_index = 0  # round robin counter

    # ADDED: smallest helper possible
    def pick_server(self):
        ip, mac = self.SERVERS[self.rr_index]
        self.rr_index = (self.rr_index + 1) % len(self.SERVERS)
        return ip, mac

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):

        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        src = eth.src
        dst = eth.dst

        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt  = pkt.get_protocol(ipv4.ipv4)

        # ----------------------------------------------------
        # ADDED: ARP RESPONSE FOR VIP
        # ----------------------------------------------------
        if arp_pkt and arp_pkt.dst_ip == self.VIP_IP:
            reply = packet.Packet()
            reply.add_protocol(ethernet.ethernet(
                ethertype=ether_types.ETH_TYPE_ARP,
                dst=src,
                src=self.VIP_MAC))
            reply.add_protocol(arp.arp(
                opcode=arp.ARP_REPLY,
                src_mac=self.VIP_MAC, src_ip=self.VIP_IP,
                dst_mac=src,        dst_ip=arp_pkt.src_ip))
            reply.serialize()

            actions = [parser.OFPActionOutput(in_port)]
            out = parser.OFPPacketOut(datapath=datapath,
                                      buffer_id=ofproto.OFP_NO_BUFFER,
                                      in_port=ofproto.OFPP_CONTROLLER,
                                      actions=actions,
                                      data=reply.data)
            datapath.send_msg(out)
            return

        # ----------------------------------------------------
        # ADDED: ROUND ROBIN VIP HANDLING
        # ----------------------------------------------------
        if ip_pkt and ip_pkt.dst == self.VIP_IP:

            # pick next backend server
            real_ip, real_mac = self.pick_server()
            self.logger.info(f"VIP packet redirected to {real_ip}")

            actions = [
                parser.OFPActionSetField(eth_dst=real_mac),
                parser.OFPActionSetField(ipv4_dst=real_ip),
                parser.OFPActionOutput(ofproto.OFPP_FLOOD)
            ]

            out = parser.OFPPacketOut(datapath=datapath,
                                      buffer_id=msg.buffer_id,
                                      in_port=in_port,
                                      actions=actions,
                                      data=msg.data)
            datapath.send_msg(out)
            return

        # ----------------------------------------------------
        # ORIGINAL SIMPLE SWITCH BEHAVIOR
        # ----------------------------------------------------
        dpid = format(datapath.id, "d").zfill(16)
        self.mac_to_port.setdefault(dpid, {})

        self.mac_to_port[dpid][src] = in_port

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            self.add_flow(datapath, 1, match, actions)

        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=actions,
                                  data=msg.data)
        datapath.send_msg(out)
