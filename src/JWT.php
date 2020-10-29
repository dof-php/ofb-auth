<?php

declare(strict_types=1);

namespace DOF\OFB\Auth;

use Closure;
use Throwable;
use DOF\Util\F;
use DOF\Util\IS;
use DOF\Util\Str;
use DOF\Util\Format;
use DOF\OFB\Auth\Exceptor\JWTExceptor;
use DOF\OFB\Auth\Exceptor\ExpiredJWT;
use DOF\OFB\Auth\Exceptor\InvalidJWT;

/**
 * Json Web Token
 */
class JWT
{
    /** @var int: Time of JWT token to live */
    private $ttl = 86400;    // default: 24h

    /** @var int|string: The secret id for signature */
    private $secretId;

    /** @var string: The secret key for signature */
    private $secretKey;

    /** @var string: Name of selected hashing algorithm (hash_hmac_algos()) */
    private $algo = 'sha256';

    /** @var bool: Remember me or not option */
    private $remember = false;

    /** @var string: Timezone shortname used for token issuing and verifying */
    private $timezone;

    /** @var int: Timestamp used for token issuing and verifying */
    private $timestamp;

    /** @var string: JWT processing environment */
    private $env;

    /** @var bool: Enable enviornment detection or not */
    private $envDetection = false;

    // callbacks
    private $onJWTIssued;
    private $onJWTExpired;

    public function issue(...$params)
    {
        if ((! \is_int($this->ttl)) || ($this->ttl < 1)) {
            throw new JWTExceptor('BAD_TOKEN_TTL_SETTING', ['ttl' => $this->ttl]);
        }
        if (((! \is_int($this->secretId)) && (! \is_string($this->secretId))) || IS::empty($this->secretId)) {
            throw new JWTExceptor('MISSING_OR_INVALID_SECRET_ID', ['id' => $this->secretId]);
        }
        if ((! \is_string($this->secretKey)) || IS::empty($this->secretKey)) {
            throw new JWTExceptor('MISSING_OR_INVALID_SECRET_KEY', ['key' => $this->secretKey]);
        }

        $ts = $this->timestamp ?? \time();

        $header = static::encode([
            'typ' => 'JWT',
            'alg' => $this->algo,
        ]);
        $claims = [
            'iss' => 'dof',    // Issuer
            // 'sub' => null,  // Subject
            // 'aud' => null,  // Audience
            // 'jti' => null,  // JWT ID
            'nbf' => $ts,      // Not Before
            'iat' => $ts,      // Issued At
            'sid' => $this->secretId,     // JWT secret key ID
            'tza' => \date('T'),          // Timezone abbreviation (custom)
            'exp' => $ts + $this->ttl,    // Expiration Time
        ];

        if ($this->remember) {
            $claims['rmb'] = 1;    // Auto renewal lifetime of this JWT
        }

        if ($this->envDetection) {
            if (! $this->env) {
                throw new JWTExceptor('UNKNOWN_JWT_ENVIRONMENT');
            }

            $claims['env'] = $this->env;    // Environment elements of this JWT when issuing or verifying
        }

        $payload = static::encode([$claims, F::unsplat(...$params)]);
        $signature = $this->sign(\join('.', [$header, $payload]), $this->algo, $this->secretKey);

        $token = \join('.', [$header, $payload, $signature]);

        if ($this->onJWTIssued) {
            try {
                $result = ($this->onJWTIssued)($token, F::unsplat(...$params));
            } catch (Throwable $th) {
                throw new JWTExceptor('AFTER_ISSUE_HOOK_FAILED', \compact('result'), $th);
            }
        }

        return $token;
    }

    /**
     * Parse JWT string to array structure
     *
     * @param string $token: JWT token to be parsed
     * @return array: array structure behind JWT string
     */
    public static function parse(string $token) : array
    {
        $data = [];

        $components = Str::arr($token, '.');
        if ($header = ($components[0] ?? null)) {
            $data['header'] = static::decode($header);
        }
        if ($payload = ($components[1] ?? null)) {
            $payload = static::decode($payload);
            $data['claims'] = $payload[0] ?? [];
            $data['payload'] = $payload[1] ?? null;
        }
        if ($signature = ($components[2] ?? null)) {
            $data['signature'] = $signature;
        }

        return $data;
    }

    /**
     * Verify a JWT token signed by dof
     *
     * @param string $token
     * @param array $parse: JWT parse result
     * @return mixed: User defined payload
     */
    public function verify(string $token, array &$parse = null)
    {
        if (IS::empty($token = \trim($token))) {
            throw new InvalidJWT('MISSING_OR_EMPTY_TOKEN');
        }
        if (! $this->secretKey) {
            throw new JWTExceptor('MISSING_TOKEN_SECRET');
        }
        $arr = \explode('.', $token);
        if (3 !== ($cnt = \count($arr))) {
            throw new InvalidJWT('INVALID_TOKEN_COMPONENT_COUNT', \compact('cnt'));
        }
        if (! ($header = $arr[0] ?? null) || (! \is_string($header))) {
            throw new InvalidJWT('MISSING_OR_BAD_TOKEN_HEADER', \compact('header'));
        }
        if (! ($payload = $arr[1] ?? null) || (! \is_string($payload))) {
            throw new InvalidJWT('INVALID_TOKEN_PAYLOAD', \compact('payload'));
        }
        if (! ($signature = $arr[2] ?? null) || (! \is_string($signature))) {
            throw new InvalidJWT('BAD_TOKEN_SIGNATURE', \compact('signature'));
        }
        if ((! ($_header = static::decode($header, true))) || (! \is_array($_header)) || (! ($alg = ($_header['alg'] ?? false)))) {
            throw new InvalidJWT('INVALID_TOKEN_HEADER', \compact('header', '_header'));
        }
        if (! \in_array($alg, \hash_algos())) {
            throw new InvalidJWT('UNSUPPORTED_ALGORITHM', \compact('alg'));
        }
        if ($signature !== $this->sign(\join('.', [$header, $payload]), $alg, $this->secretKey)) {
            throw new InvalidJWT('INVALID_JWT_SIGNATURE', \compact('signature'));
        }
        $data = static::decode($payload, true);
        if ((! ($tza = $data[0]['tza'] ?? null)) || (! Str::eq($tza, ($this->timezone ?? \date('T')), true))) {
            throw new InvalidJWT('INVALID_TOKEN_TIMEZONE', \compact('tza'));
        }
        if ($this->envDetection) {
            if (! ($env = $data[0]['env'] ?? null)) {
                throw new InvalidJWT('MISSING_ENVIRONMENT_IN_CLAIMS');
            }
            if (! $this->env) {
                throw new JWTExceptor('UNKNOWN_JWT_ENVIRONMENT');
            }
            if ($env !== $this->env) {
                throw new InvalidJWT('INVALID_JWT_ENVIRONMENT');
            }
        }
        if ((! ($exp = $data[0]['exp'] ?? null)) || (! IS::timestamp($exp))) {
            throw new InvalidJWT('INVALID_TOKEN_EXPIRE_TIME', \compact('exp'));
        }
        $params = $data[1] ?? [];
        if (($this->timestamp ?? \time()) > $exp) {
            // $rmb = $data[0]['rmb'] ?? null;
            // if ($rmb) {
            // TODO remember me
            // }

            if ($this->onJWTExpired) {
                try {
                    ($this->onJWTExpired)($token, $params);
                } catch (Throwable $th) {
                    throw new JWTExceptor('ON_JWT_EXPIRED_CALLBACK_EXCEPTION', $th);
                }
            }

            throw new ExpiredJWT(\compact('exp', 'tza'));
        }

        if (\is_array($parse)) {
            $parse = [
                'header' => $_header,
                'claims' => $data[0] ?? [],
                'payload' => $data[1] ?? null,
                'signature' => $signature
            ];
        }

        return $params;
    }

    /**
     * Sign a text string with jwt flavor
     *
     * @param string $text
     * @param string $algo
     * @param string $secret
     * @return string
     * @throw
     */
    public function sign(string $text, string $algo, string $secret)
    {
        if (! \in_array($algo, \hash_algos())) {
            throw new JWTExceptor('UNSUPPORTED_ALGORITHM', \compact('algo'));
        }

        return Format::enbase64(\hash_hmac($algo, $text, $secret), true);
    }

    /**
     * Decode a jwt token into php structure
     *
     * @param string $token
     * @param bool $array: Return as array or not
     */
    public static function decode(string $token, bool $array = true)
    {
        return \json_decode(Format::debase64($token, true), $array);
    }

    /**
     * Encode a php array into jwt flavor token
     *
     * @param array $data
     */
    public static function encode(array $data)
    {
        return Format::enbase64(\json_encode($data), true);
    }

    public function setSecretId($id)
    {
        $this->secretId = $id;

        return $this;
    }

    public function setSecretKey(string $key)
    {
        $this->secretKey = $key;

        return $this;
    }

    public function setTTL(int $ttl)
    {
        $this->ttl = $ttl;

        return $this;
    }

    public function setAlgo(string $algo)
    {
        $this->algo = \strtolower($algo);

        return $this;
    }

    public function setRemember(bool $remember)
    {
        $this->remember = $remember;

        return $this;
    }

    public function setTimestamp(int $timestamp)
    {
        $this->timestamp = $timestamp;

        return $this;
    }

    public function setTimezone(string $timezone)
    {
        $this->timezone = $timezone;

        return $this;
    }

    public function setEnv(string $env)
    {
        $this->env = $env;

        return $this;
    }

    public function setEnvDetection(bool $envDetection)
    {
        $this->envDetection = $envDetection;

        return $this;
    }

    public function setOnJWTIssued(Closure $onJWTIssued)
    {
        $this->onJWTIssued = $onJWTIssued;

        return $this;
    }

    public function setOnJWTExpired(Closure $onJWTExpired)
    {
        $this->onJWTExpired = $onJWTExpired;

        return $this;
    }
}
