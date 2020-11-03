<?php

namespace DOF\OFB\Auth\SDK\V1;

use Exception;

// JWT issuer for older PHP version use
class CompatibleJWTIssuer
{
    private $ttl = 86400;
    private $secretId;
    private $secretKey;
    private $algo = 'sha256';
    private $remember = false;
    private $timezone;
    private $env;
    private $envDetection = false;

    public function issue($params)
    {
        if ((! \is_int($this->ttl)) || ($this->ttl < 1)) {
            throw new Exception('BAD_TOKEN_TTL_SETTING');
        }
        if (((! \is_int($this->secretId)) && (! \is_string($this->secretId))) || empty($this->secretId)) {
            throw new Exception('MISSING_OR_INVALID_SECRET_ID');
        }
        if ((! \is_string($this->secretKey)) || empty($this->secretKey)) {
            throw new Exception('MISSING_OR_INVALID_SECRET_KEY');
        }

        $ts = $this->timezone > 0 ? $this->timezone : \time();

        $header = static::encode([
            'typ' => 'JWT',
            'alg' => $this->algo,
            'kid' => $this->secretId,
        ]);
        $claims = [
            'iss' => 'dof',
            'exp' => $ts + $this->ttl,
            'nbf' => $ts,
            'iat' => $ts,
            'tza' => $this->timezone ?: \date('T'),
        ];

        if ($this->remember) {
            $claims['rmb'] = 1;
        }

        if ($this->envDetection) {
            if (! $this->env) {
                throw new Exception('UNKNOWN_JWT_ENVIRONMENT');
            }

            $claims['env'] = $this->env;
        }

        $payload = static::encode([$claims, $params]);
        $signature = static::sign(\join('.', [$header, $payload]), $this->algo, $this->secretKey);

        return \join('.', [$header, $payload, $signature]);
    }

    public static function sign($text, $algo, $secret)
    {
        if (! \in_array($algo, \hash_algos())) {
            throw new Exception('UNSUPPORTED_ALGORITHM');
        }

        return \rtrim(\strtr(\base64_encode(\hash_hmac($algo, $text, $secret)), '+/', '-_'), '=');
    }

    public static function decode($token, $array = true)
    {
        return \json_decode(\base64_decode(\str_pad(\strtr($token, '-_', '+/'), \strlen($token) % 4, '=', STR_PAD_RIGHT)), $array);
    }

    public static function encode($data)
    {
        return \rtrim(\strtr(\base64_encode(\json_encode($data)), '+/', '-_'), '=');
    }

    public function setTTL(int $ttl)
    {
        $this->ttl = $ttl;

        return $this;
    }

    public function setSecretId($id)
    {
        $this->secretId = $id;

        return $this;
    }

    public function setSecretKey($key)
    {
        $this->secretKey = $key;

        return $this;
    }

    public function setTimestamp($timestamp)
    {
        $this->timestamp = $timestamp;

        return $this;
    }

    public function setTimezone($timezone)
    {
        $this->timezone = $timezone;

        return $this;
    }

    public function setRemember($remember)
    {
        $this->remember = $remember;

        return $this;
    }

    public function setEnv($env)
    {
        $this->env = $env;

        return $this;
    }

    public function setEnvDetection($envDetection)
    {
        $this->envDetection = $envDetection;

        return $this;
    }

    public function setAlgo($algo)
    {
        $this->algo = \strtolower($algo);

        return $this;
    }
}
