<?php

declare(strict_types=1);

namespace DOF\OFB\Auth\Pipe;

use Throwable;
use DOF\ENV;
use DOF\Util\IS;
use DOF\Util\Str;
use DOF\Util\Format;
use DOF\OFB\Auth\Exceptor\ExpiredJWT;
use DOF\OFB\Auth\Exceptor\InvalidJWT;
use DOF\OFB\Auth\Surrogate\JWT;

/**
 * AUTHORIZATION: Bearer {token}
 */
class BearerAuth
{
    /** @var string: The bearer auth token found in request */
    protected $token;

    /** @var string: The token secret used for signature, can be overwrite by subclass */
    protected $secret = 'BEAR_AUTH_TOKEN_SECRET';

    /** @var string: The parameter key to store authenticated user id */
    protected $authid = 'uid';

    /** @var string: The parameter key to store forward user ids */
    protected $authidForward = 'fid';

    /** @var array: The parameter names will be checked in request when AUTHORIZATION header not found */
    protected $allowTokenParameters = ['__token', '__bearer_token', '__auth_token'];

    final public function pipein($request, $response, $route, $port)
    {
        $header = \trim((string) $request->getHeader('AUTHORIZATION'));
        if ($header) {
            if (! Str::eq(Str::first($header, 7), 'Bearer ', true)) {
                return $response->abort(401, 'INVALID_BEARER_TOKEN');
            }
            $token = Str::last($header, 7, false);
        } elseif ($this->allowTokenParameters) {
            $token = (string) $request->match($this->allowTokenParameters);
        }

        if ((! isset($token)) || IS::empty($token = \trim($token))) {
            return $response->abort(401, 'MISSING_TOKEN_HEADER_OR_PARAMETER');
        }

        // parse and get secret id
        $data = JWT::parse($token);
        if (\is_null($skid = ($data['header']['kid'] ?? null)) || ((! \is_string($skid)) && (! \is_int($skid)))) {
            return $response->exceptor('MISSING_OR_INVALID_TOKEN_SECRET_KEY_ID', compact('skid'));
        }

        $static = static::class;
        $secret = ($static === __CLASS__) ? ENV::systemGet($this->secret) : ENV::final($static, $this->secret);
        if ((! $secret) || (! \is_array($secret))) {
            return $response->exceptor('MISSING_OR_INVALID_TOKEN_SECRET', [
                'key' => $this->secret,
                'ns'  => $static,
            ]);
        }
        if (\is_null($skey = $secret[$skid] ?? null) || IS::empty($skey) || (! \is_string($skey))) {
            return $response->exceptor('MISSING_OR_NONSTRING_TOKEN_SECRET_KEY');
        }

        try {
            $jwt = JWT::setSecretKey($skey);

            if (\method_exists($this, 'onJWTExpired')) {
                $jwt->setOnJWTExpired(function ($token, $params) {
                    $this->onJWTExpired($token, $params);
                });
            }

            if ($this->envDetection()) {
                $jwt->setEnvDetection(true)->setEnv($this->getJWTEnv($request));
            }

            // $parse = [];
            // $argvs = $jwt->verify($token, $parse);
            $argvs = $jwt->verify($token);

            $route->setPipein(static::class, Format::collect([
                'token' => $token,
                'argvs' => $argvs,
            ]));
        } catch (ExpiredJWT $th) {
            return $response->abort(401, 'EXPIRED_JWT', $th);
        } catch (InvalidJWT $th) {
            return $response->abort(401, 'INVALID_JWT', $th);
        } catch (Throwable $th) {
            return $response->throw($th);
        }

        $this->token = $token;

        return true;
    }

    protected function envDetection() : bool
    {
        return false;
    }

    protected function getJWTEnv($request) : string
    {
        return \md5(\join('.', [
            $request->getClientUA(),
            $request->getClientIp(),
            $request->getClientIp(true)
        ]));
    }
}
