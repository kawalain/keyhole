<?php

/*
 * keyhole: OPNsense hooks. Registers the pf anchor keyhole loads its own
 * rules into (ADR 0007) and lists the service, both only while keyhole is
 * enabled.
 */

function keyhole_enabled()
{
    $mdl = new \OPNsense\Keyhole\Keyhole();
    return !$mdl->general->enabled->isEmpty();
}

function keyhole_firewall(\OPNsense\Firewall\Plugin $fw)
{
    if (!keyhole_enabled()) {
        return;
    }
    // keyhole only redirects (ADR 0014), so a translation anchor is enough.
    // Translation rules are first-match already; pf rejects "quick" on them.
    $fw->registerAnchor('keyhole', 'rdr', 0, 'head');
}

function keyhole_services()
{
    $services = [];
    if (keyhole_enabled()) {
        $services[] = [
            'description' => gettext('keyhole censorship bypass'),
            'configd' => [
                'start' => ['keyhole start'],
                'restart' => ['keyhole restart'],
                'stop' => ['keyhole stop'],
            ],
            'name' => 'keyhole',
            'pidfile' => '/var/run/keyhole.pid',
        ];
    }
    return $services;
}
