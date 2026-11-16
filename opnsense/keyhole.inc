<?php

/*
 * keyhole: registers the pf anchors keyhole loads its own rules into
 * (ADR 0007). Installed as /usr/local/etc/inc/plugins.inc.d/keyhole.inc;
 * OPNsense calls keyhole_firewall() whenever it generates the ruleset.
 */

function keyhole_firewall(\OPNsense\Firewall\Plugin $fw)
{
    // Translation rules are first-match already; pf rejects "quick" on them.
    $fw->registerAnchor('keyhole', 'rdr', 0, 'head');
    $fw->registerAnchor('keyhole', 'fw', 0, 'head', true);
}
