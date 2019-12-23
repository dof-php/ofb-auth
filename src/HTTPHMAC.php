<?php

declare(strict_types=1);

namespace DOF\OFB\Auth;

use DOF\OFB\Auth\Exceptor\HTTPHMACExceptor;

class HTTPHMAC extends HMAC
{
    protected $implementor = 'dof-php-http-hmac';

    /** @var string: Request host */
    private $host;    #10

    /** @var string: Request verb */
    private $verb;    #11

    /** @var string: Request path */
    private $path;    #12

    /** @var array: Request Headers */
    private $headers = [];    #13

    public function prepare()
    {
        parent::prepare();

        if (! $this->verb) {
            throw new HTTPHMACExceptor('MISSING_HTTP_HMAC_VERB');
        }
        if (! $this->host) {
            throw new HTTPHMACExceptor('MISSING_HTTP_HMAC_HOST');
        }
        if (! $this->path) {
            throw new HTTPHMACExceptor('MISSING_HTTP_HMAC_PATH');
        }
    }

    public function build()
    {
        $this->prepare();

        return \join("\n", [
            $this->version,
            $this->implementor,
            $this->algorithm,
            $this->realm,
            $this->client,
            $this->timestamp,
            $this->nonce,
            $this->stringify($this->parameters),
            $this->stringify($this->more),
            $this->host,
            $this->verb,
            $this->path,
            $this->stringify($this->headers),
        ]);
    }

    /**
     * Getter for headers
     *
     * @return array
     */
    public function getHeaders(): array
    {
        return $this->headers;
    }
    
    /**
     * Setter for headers
     *
     * @param array $headers
     * @return HTTPHMAC
     */
    public function setHeaders(array $headers)
    {
        foreach ($headers as $key => $val) {
            if (\is_int($key)) {
                throw new HTTPHMACExceptor('BAD_HEADER_KEY', \compact('key'));
            }
            if (! \is_string($val)) {
                throw new HTTPHMACExceptor('BAD_HEADER_VALUE', \compact('val'));
            }
        }

        $this->headers = $headers;
    
        return $this;
    }

    /**
     * Getter for verb
     *
     * @return string
     */
    public function getVerb(): string
    {
        return $this->verb;
    }
    
    /**
     * Setter for verb
     *
     * @param string $verb
     * @return HTTPHMAC
     */
    public function setVerb(string $verb)
    {
        $this->verb = \urlencode($verb);
    
        return $this;
    }

    /**
     * Getter for host
     *
     * @return string
     */
    public function getHost(): string
    {
        return $this->host;
    }
    
    /**
     * Setter for host
     *
     * @param string $host
     * @return HTTPHMAC
     */
    public function setHost(string $host)
    {
        $this->host = \urlencode($host);
    
        return $this;
    }

    /**
     * Getter for path
     *
     * @return string
     */
    public function getPath(): string
    {
        return $this->path;
    }
    
    /**
     * Setter for path
     *
     * @param string $path
     * @return HTTPHMAC
     */
    public function setPath(string $path)
    {
        $this->path = \urlencode($path);
    
        return $this;
    }
}
