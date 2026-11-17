import json
import os

from ryu.app import simple_switch_13
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, set_ev_cls
from ryu.lib import hub

POLICY_FILE = os.path.expanduser('~/ryu-lab/policy.json')
BLOCK_PRIORITY = 100


class AccessControl(simple_switch_13.SimpleSwitch13):
    def __init__(self, *args, **kwargs):
        super(AccessControl, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.blocked = set()
        hub.spawn(self._watch_policy)

    def _read_policy(self):
        try:
            with open(POLICY_FILE) as f:
                data = json.load(f)
            return set((a, b) for a, b in data.get('blocked', []))
        except Exception as e:
            self.logger.warning('Could not read policy: %s', e)
            return self.blocked

    def _drop_rule(self, dp, pair, delete=False):
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        match = parser.OFPMatch(eth_type=0x0800,
                                ipv4_src=pair[0], ipv4_dst=pair[1])
        if delete:
            mod = parser.OFPFlowMod(
                datapath=dp, command=ofp.OFPFC_DELETE_STRICT,
                out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                priority=BLOCK_PRIORITY, match=match)
        else:
            mod = parser.OFPFlowMod(
                datapath=dp, priority=BLOCK_PRIORITY,
                match=match, instructions=[])  # no actions = drop
        dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def acl_switch_connected(self, ev):
        dp = ev.msg.datapath
        self.datapaths[dp.id] = dp
        self.blocked = self._read_policy()
        for pair in self.blocked:
            self._drop_rule(dp, pair)
        self.logger.info('ACL: switch connected, blocking %s',
                         sorted(self.blocked))

    def _watch_policy(self):
        while True:
            hub.sleep(2)
            new = self._read_policy()
            if new == self.blocked:
                continue
            for dp in self.datapaths.values():
                for pair in self.blocked - new:
                    self._drop_rule(dp, pair, delete=True)
                for pair in new - self.blocked:
                    self._drop_rule(dp, pair)
            self.logger.info('ACL: policy changed, now blocking %s',
                             sorted(new))
            self.blocked = new
