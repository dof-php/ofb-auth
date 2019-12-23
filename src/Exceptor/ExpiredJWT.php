<?php

declare(strict_types=1);

namespace DOF\OFB\Auth\Exceptor;

use DOF\Util\Exceptor;

class ExpiredJWT extends Exceptor
{
    public $tags = [
        Exceptor::TAG_CLIENT => true,
    ];
}
