<?php

declare(strict_types=1);

namespace DOF\OFB\Auth\Surrogate;

use DOF\Util\Surrogate;
use DOF\OFB\Auth\JWT as Instance;

final class JWT extends Surrogate
{
    public static function namespace() : string
    {
        return Instance::class;
    }
}
