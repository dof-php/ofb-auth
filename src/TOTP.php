<?php

declare(strict_types=1);

namespace DOF\OFB\Auth;

use DOF\Util\F;
use DOF\Util\Str;
use DOF\Util\Rand;

// [Time-based One-time Password](https://tools.ietf.org/html/rfc6238)
// One widely used type of Two-factor authentication
// Use one-time password calculated by certified mobile phone as 2FA
// TODO
class TOTP
{
    const MIN_SECRET_LEN = 32;

    // Generate a dynamic random string as secret
    // Secret should be saved in TOTP app on mobile phone (like Google Authenticator)
    public static function getSecret(int $length = 40, int $ttl = 30, bool $qrcode = false)
    {
        $base = \strtoupper(\md5(\join('.', [$ttl, Rand::int(), F::nanoseconds()])));

        if ($length < self::MIN_SECRET_LEN) {
            return $base;
        }

        return Rand::ascii($length - self::MIN_SECRET_LEN).$base;
    }

    // Generate a dynamic secret string by given id
    public static function getSecretByID(
        int $id,
        int $length = 40,
        int $ttl = 30,
        bool $qrcode = false
    ) : string {
        $base = \strtoupper(\md5(\join('.', [$id, $ttl, \microtime()])));

        if ($length < self::MIN_SECRET_LEN) {
            return $base;
        }

        return Rand::ascii($length - self::MIN_SECRET_LEN).$base;
    }

    // Generate a dynamic secret string by given key
    public static function getSecretByKey(
        string $key,
        int $length = 40,
        int $ttl = 30,
        bool $qrcode = false
    ) : string {
        $base = \strtoupper(\md5(\join('.', [$key, $ttl, \microtime()])));

        if ($length < self::MIN_SECRET_LEN) {
            return $base;
        }

        return Rand::ascii($length - self::MIN_SECRET_LEN).$base;
    }

    // TC = \floor((unixtime(now) − unixtime(T0)) / TS)
    public static function verify(
        string $code,
        string $secret,
        string $algo = 'sha1',
        int $ttl = 30,
        int $timestamp = null,
        int $t0 = 0,
        string $timezone = null
    ) : bool {
        $timestamp = $timestamp ?? \time();
        $tc = \floor(($timestamp - $t0) / $ttl);
        $totp = \hash_hmac($algo, $tc, $secret);
        if (false === $totp) {
            return false;
        }

        return Str::eq($code, $totp, true);
    }
}
