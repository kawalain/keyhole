<?php

namespace OPNsense\Keyhole\Api;

use OPNsense\Base\ApiMutableServiceControllerBase;
use OPNsense\Core\Backend;

class ServiceController extends ApiMutableServiceControllerBase
{
    protected static $internalServiceClass = '\OPNsense\Keyhole\Keyhole';
    protected static $internalServiceTemplate = 'OPNsense/Keyhole';
    protected static $internalServiceEnabled = 'general.enabled';
    protected static $internalServiceName = 'keyhole';

    /**
     * Besides restarting keyhole, reload the firewall (the anchors exist
     * only while keyhole is enabled) and Unbound (it forwards to keyhole
     * only while keyhole is enabled).
     */
    public function reconfigureAction()
    {
        $result = parent::reconfigureAction();
        if ($this->request->isPost()) {
            $backend = new Backend();
            $backend->configdRun('filter reload');
            $backend->configdRun('unbound restart');
        }
        return $result;
    }
}
