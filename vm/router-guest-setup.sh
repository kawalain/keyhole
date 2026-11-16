#!/bin/sh
# Runs inside the router VM (sent by setup-router.sh). Test VM only: it lets
# root in over SSH with one key, from the WAN side that only the host's
# QEMU port forward can reach.
set -eu

mkdir -p /root/.ssh
chmod 700 /root/.ssh
echo '@PUBKEY@' > /root/.ssh/authorized_keys
chmod 600 /root/.ssh/authorized_keys

php <<'PHP'
<?php
require_once('config.inc');
use OPNsense\Core\Config;
$config = Config::getInstance();
$c = $config->object();
$c->system->ssh->enabled = 'enabled';
$c->system->ssh->permitrootlogin = '1';
// OPNsense rewrites authorized_keys from the user record at boot.
foreach ($c->system->user as $user) {
    if ((string)$user->name === 'root') {
        $user->authorizedkeys = base64_encode('@PUBKEY@' . "\n");
    }
}
// QEMU's NAT presents the host as 10.0.2.2, a private address.
unset($c->interfaces->wan->blockpriv);
unset($c->interfaces->wan->blockbogons);
$exists = false;
foreach ($c->OPNsense->Firewall->Filter->rules->rule as $rule) {
    $exists = $exists || (string)$rule->description === 'keyhole-vm ssh';
}
if (!$exists) {
    $rule = $c->OPNsense->Firewall->Filter->rules->addChild('rule');
    $rule->addAttribute('uuid', '6b0e2f6a-5d8c-4f4e-9a51-3f0c1a2b9e01');
    $fields = [
        'enabled' => '1', 'statetype' => 'keep', 'sequence' => '2',
        'action' => 'pass', 'quick' => '1', 'interfacenot' => '0',
        'interface' => 'wan', 'direction' => 'in', 'ipprotocol' => 'inet',
        'protocol' => 'TCP', 'source_net' => 'any', 'source_not' => '0',
        'destination_net' => 'any', 'destination_not' => '0',
        'destination_port' => '22', 'description' => 'keyhole-vm ssh',
    ];
    foreach ($fields as $k => $v) {
        $rule->addChild($k, $v);
    }
}
$config->save();
echo "config saved\n";
PHP

configctl interface reconfigure wan || true
configctl filter reload
configctl openssh restart
sleep 2
pfctl -sr | grep -n 'port = 22\|port = ssh' || echo 'no ssh rule in pf'
sockstat -4l | grep ':22 ' || echo 'sshd not listening'
