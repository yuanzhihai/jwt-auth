<?php

namespace thans\jwt\claim;

use think\Request;
use thans\jwt\support\Utils;

class Factory
{
    protected $classMap = [
        'aud' => Audience::class,
        'exp' => Expiration::class,
        'iat' => IssuedAt::class,
        'iss' => Issuer::class,
        'jti' => JwtId::class,
        'nbf' => NotBefore::class,
        'sub' => Subject::class,
    ];

    /**
     * The required claims.
     *
     * @var array
     */
    protected $requiredClaims = [
        'iss',
        'iat',
        'exp',
        'nbf',
        'sub',
        'jti',
    ];

    /**
     * Time leeway in seconds.
     *
     * @var int
     */
    protected $leeway = 0;
    protected $ttl;
    protected $claim = [];
    protected $refreshTtl = 20160;

    public function __construct(Request $request, $ttl, $refreshTtl)
    {
        $this->request    = $request;
        $this->ttl        = $ttl;
        $this->refreshTtl = $refreshTtl;
    }

    public function customer($key, $value)
    {
        if ($this->has($key)) {
            $this->claim[$key] = new $this->classMap[$key]($value);
            return method_exists($this->claim[$key], 'setLeeway') ?
                $this->claim[$key]->setLeeway($this->leeway) :
                $this->claim[$key];
        }
        $this->claim[$key] = new Customer($key, $value);
        return $this;
    }

    public function has($name)
    {
        return array_key_exists($name, $this->classMap);
    }


    public function builder()
    {
        foreach ($this->classMap as $key => $class) {
            if (in_array($key, $this->requiredClaims)) {
                $claim[$key] = new $class(method_exists($this, $key)
                    ? $this->$key() : '');
            }
        }
        $this->claim = array_merge($this->claim, $claim);
        return $this;
    }

    public function validate($refresh = false)
    {
        foreach ($this->claim as $key => $claim) {
            if (!$refresh && method_exists($claim, 'validatePayload')) {
                $claim->validatePayload();
            }
            if ($refresh && method_exists($claim, 'validateRefresh')) {
                $claim->validateRefresh($this->refreshTtl);
            }
        }
    }

    public function setRequiredClaims(array $claims)
    {
        $this->requiredClaims = $claims;
        return $this;
    }

    public function setRefreshTTL($ttl)
    {
        $this->refreshTtl = $ttl;
    }


    public function getClaims()
    {
        return $this->claim;
    }

    public function aud()
    {
        return $this->request->url();
    }

    public function exp()
    {
        return Utils::now()->addSeconds($this->ttl)->getTimestamp();
    }

    public function iat()
    {
        return Utils::now()->getTimestamp();
    }

    public function iss()
    {
        return $this->request->url();
    }

    public function jti()
    {
        return md5(uniqid() . time() . rand(100000, 9999999));
    }

    public function nbf()
    {
        return Utils::now()->getTimestamp();
    }

    public function setLeeway($leeway)
    {
        $this->leeway = $leeway;
        return $this;
    }
}
