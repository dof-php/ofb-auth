<?php

declare(strict_types=1);

namespace DOF\OFB\Auth;

use DOF\Util\IS;
use DOF\OFB\Auth\Surrogate\JWT;

class Command
{
    /**
     * @CMD(jwt.parse)
     * @Desc(Parse JWT string to array)
     * @Argv(#1){notes=JWT string}
     */
    public function parseJWT($console)
    {
        $jwt = $console->first();
        if (IS::empty($jwt)) {
            $console->fail('MISSING_JWT');
            return;
        }

        $console->line(JWT::parse($jwt));
    }
}
