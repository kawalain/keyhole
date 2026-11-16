<?php

namespace OPNsense\Keyhole\Api;

use OPNsense\Base\ApiMutableModelControllerBase;

class SettingsController extends ApiMutableModelControllerBase
{
    protected static $internalModelClass = '\OPNsense\Keyhole\Keyhole';
    protected static $internalModelName = 'keyhole';
}
