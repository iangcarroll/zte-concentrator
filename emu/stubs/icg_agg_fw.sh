#!/bin/sh
# Stand-in for the device's /sbin/icg_agg_fw.sh.
#
# The real one installs the netfilter and policy-routing plumbing, including a
# blanket DROP on the LAN bridge when AggregationServerTunIP is empty — which
# is how enabling SMULTIWAN without a reachable concentrator cuts a device off.
# None of that is wanted here: we are testing the tunnel, not the firewall, and
# the container has no LAN to protect. Logged so its absence is visible.
echo "[stub] icg_agg_fw.sh called with: $*" >&2
exit 0
