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

    public function pipein($request, $response, $route, $port)
    {
        $header = \trim((string) $request->getHeader('AUTHORIZATION'));
        $token  = '';
        if ($header) {
            if (! Str::eq(Str::first($header, 7), 'Bearer ', true)) {
                return $response->abort(401, 'INVALID_BEARER_TOKEN');
            }

            $token = \mb_substr($header, 7);
        } elseif ($this->allowTokenParameters) {
            $key   = null;
            $token = (string) $request->match($this->allowTokenParameters, $key);
        }

        $token = \trim($token);
        if (! $token) {
            return $response->abort(401, 'MISSING_TOKEN_HEADER_OR_PARAMETER');
        }

        $secret = ENV::final(static::class, $this->secret);
        if ((! $secret) || (! \is_array($secret))) {
            return $response->exceptor('MISSING_OR_INVALID_TOKEN_SECRET', [
                'key' => $this->secret,
                'ns'  => static::class,
            ]);
        }
        $id = $secret[0] ?? null;
        if (\is_null($id) || (! \is_int($id))) {
            return $response->exceptor('MISSING_OR_NON_INT_TOKEN_SECRET_ID');
        }
        $key = $secret[1] ?? null;
        if (\is_null($key) || IS::empty($key) || (! \is_string($key))) {
            return $response->exceptor('MISSING_OR_NON_STRING_TOKEN_SECRET_ID');
        }

        try {
            $jwt = JWT::setSecretId($id)->setSecretKey($key);

            if (\method_exists($this, 'beforeTokenVerify')) {
                $jwt->setBeforeVerify(function ($token) {
                    $this->beforeTokenVerify($token);
                });
            }
            if (\method_exists($this, 'afterTokenVerify')) {
                $jwt->setAfterVerify(function ($params, $token) {
                    $this->afterTokenVerify($params, $token);
                });
            }
            if (\method_exists($this, 'onTokenVerifyExpired')) {
                $jwt->setOnTokenVerifyExpired(function ($token, $params) {
                    $this->onTokenVerifyExpired($token, $params);
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
