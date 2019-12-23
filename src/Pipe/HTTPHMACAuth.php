<?php

declare(strict_types=1);

namespace DOF\OFB\Auth\Pipe;

use Throwable;
use DOF\Util\IS;
use DOF\Util\Str;
use DOF\Util\Format;
use DOF\Util\Singleton;
use DOF\OFB\Auth\HTTPHMAC;
use DOF\OFB\Auth\Exceptor\TimeoutedHMACSignature;

/**
 * AUTHORIZATION: http-hmac {token}
 */
abstract class HTTPHMACAuth
{
    public function pipein($request, $response, $route, $port)
    {
        $header = \trim((string) $request->getHeader('AUTHORIZATION'));
        if (! $header) {
            return $response->abort(401, 'MISSING_HTTP_HMAC_TOKEN_HEADER');
        }
        if (! Str::eq(\mb_substr($header, 0, 10), 'http-hmac ', true)) {
            return $response->abort(401, 'INVALID_HTTP_HMAC_TOKEN');
        }

        $token = \mb_substr($header, 10);
        if (! $token) {
            return $response->abort(401, 'MISSING_TOKEN_IN_HEADER');
        }

        $data = \base64_decode($token);
        if (! \is_string($data)) {
            return $response->abort(401, 'INVALID_TOKEN_IN_HEADER', ['err' => 'Non-string token raw']);
        }
        $data = \explode("\n", $data);
        $data = \array_values($data);
        if (\count($data) !== 10) {
            return $response->abort(401, 'INVALID_TOKEN_IN_HEADER', ['err' => 'Params count mis-match']);
        }

        list(
            $version,
            $implementor,
            $algorithm,
            $realm,
            $client,
            $timestamp,
            $nonce,
            $more,
            $headers,
            $signature
        ) = $data;

        if (! $signature) {
            return $response->abort(401, 'MISSING_SIGNATURE_IN_TOKEN');
        }

        $_more = [];
        \parse_str(\urldecode($more), $_more);
        $_headers = [];
        \parse_str(\urldecode($headers), $_headers);

        try {
            $result = Singleton::get(HTTPHMAC::class)
                ->setSignature($signature)
                ->setSecret($this->getSecret($realm, $client, $port->get('class')))
                ->setVersion($version)
                ->setImplementor($implementor)
                ->setAlgorithm($algorithm)
                ->setRealm($realm)
                ->setClient($client)
                ->setTimestamp(\intval($timestamp))
                ->setNonce($nonce)
                ->setParameters($this->parameters($request))
                ->setMore($_more)
                ->setHost($this->host())
                ->setVerb($this->verb())
                ->setPath($this->path())
                ->setHeaders($_headers)
                ->setTimeoutCheck(\boolval($this->timeoutCheck()))
                ->setTimeoutDeviation(\intval($this->timeoutDeviation()))
                ->setTimestampCheck(\boolval($this->timestampCheck()))
                ->verify();

            if ($result !== true) {
                return $response->abort(401, 'INVALID_HTTP_HMAC_TOKEN_SIGNATURE');
            }

            $route->params->pipe->set(static::class, Format::collect([
                'appid' => $client,
                'client' => $realm,
            ]));

            return true;
        } catch (TimeoutedHMACSignature $th) {
            return $response->throw(401, 'TIMEOUTED_HMAC_SIGNATURE', $th);
        } catch (Throwable $th) {
            return $response->abort(401, 'HTTP_HMAC_TOKEN_VERIFY_FAILED', $th);
        }
    }

    public function timeoutCheck()
    {
        return true;
    }

    public function timeoutDeviation()
    {
        return 30;
    }

    public function timestampCheck()
    {
        return true;
    }

    public function parameters($request) : array
    {
        if ($request->hasHeader('DOF-HTTP-HMAC-ARGV')) {
            return (array) JSON::decode($request->getHeader('DOF-HTTP-HMAC-ARGV'));
        }

        return $request->all();
    }

    public function path($request) : string
    {
        if ($request->hasHeader('DOF-HTTP-HMAC-PATH')) {
            return $request->getHeader('DOF-HTTP-HMAC-PATH');
        }

        return $request->getUriRaw();
    }

    public function host($request) : string
    {
        if ($request->hasHeader('DOF-HTTP-HMAC-HOST')) {
            return $request->getHeader('DOF-HTTP-HMAC-HOST');
        }

        return $request->getHost();
    }

    public function verb($request) : string
    {
        if ($request->hasHeader('DOF-HTTP-HMAC-VERB')) {
            return $request->getHeader('DOF-HTTP-HMAC-VERB');
        }

        return $request->getMethod();
    }

    /**
     * Get Http Hmac auth client secret
     *
     * @param string $relam: Client Realm
     * @param string $client: AppId
     * @param string $domain: domain class namespace
     *
     * @return string : AppKey
     */
    abstract public function getSecret(string $realm, string $client, string $domain) : string;
}
