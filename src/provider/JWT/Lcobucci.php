<?php

namespace thans\jwt\provider\JWT;

use Exception;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Ecdsa;
use Lcobucci\JWT\Signer\Ecdsa\Sha256 as ES256;
use Lcobucci\JWT\Signer\Ecdsa\Sha384 as ES384;
use Lcobucci\JWT\Signer\Ecdsa\Sha512 as ES512;
use Lcobucci\JWT\Signer\Hmac\Sha256 as HS256;
use Lcobucci\JWT\Signer\Hmac\Sha384 as HS384;
use Lcobucci\JWT\Signer\Hmac\Sha512 as HS512;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa;
use Lcobucci\JWT\Signer\Rsa\Sha256 as RS256;
use Lcobucci\JWT\Signer\Rsa\Sha384 as RS384;
use Lcobucci\JWT\Signer\Rsa\Sha512 as RS512;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use ReflectionClass;
use thans\jwt\exception\JWTException;
use thans\jwt\exception\TokenInvalidException;
use think\Collection;

class Lcobucci extends Provider
{
    protected $signers = [
        'HS256' => HS256::class,
        'HS384' => HS384::class,
        'HS512' => HS512::class,
        'RS256' => RS256::class,
        'RS384' => RS384::class,
        'RS512' => RS512::class,
        'ES256' => ES256::class,
        'ES384' => ES384::class,
        'ES512' => ES512::class,
    ];
    /**
     * The Configuration instance.
     *
     * @var Configuration
     */
    protected $config;


    /** @var \Lcobucci\JWT\Signer The signer chosen based on the aglo. */
    protected $signer;

    /** @var Builder */
    protected $builder;

    public function __construct($secret, $algo, array $keys, $config = null)
    {
        $this->secret = $secret;
        $this->algo   = $algo;
        $this->keys   = $keys;
        $this->signer = $this->getSigner();
        if (!is_null($config)) {
            $this->config = $config;
        } elseif ($this->isAsymmetric()) {
            $this->config = Configuration::forAsymmetricSigner($this->signer, $this->getSigningKey(), $this->getVerificationKey());
        } else {
            $this->config = Configuration::forSymmetricSigner($this->signer, InMemory::plainText($this->getSecret()));
        }
        if (!count($this->config->validationConstraints())) {
            $this->config->setValidationConstraints(
                new SignedWith($this->signer, $this->getVerificationKey()),
            );
        }
    }

    /**
     * Gets the {@see $config} attribute.
     *
     * @return Configuration
     */
    public function getConfig()
    {
        return $this->config;
    }

    /**
     * Create a JSON Web Token.
     *
     * @param array $payload
     * @return string
     *
     * @throws \thans\jwt\exception\JWTException
     */
    public function encode(array $payload)
    {
        $this->builder = $this->getBuilderFromClaims($payload);
        try {
            return $this->builder->getToken($this->config->signer(), $this->config->signingKey())->toString();
        } catch (Exception $e) {
            throw new JWTException('Could not create token: ' . $e->getMessage(), $e->getCode(), $e);
        }
    }

    /**
     * Create an instance of the builder with all of the claims applied.
     * Adds a claim to the {@see $config}.
     * @param array $payload
     * @return \Lcobucci\JWT\Token\Builder
     */
    protected function getBuilderFromClaims(array $payload): Builder
    {
        $builder = $this->config->builder();
        foreach ($payload as $key => $value) {
            switch ($key) {
                case RegisteredClaims::ID:
                    $builder->identifiedBy($value);
                    break;
                case RegisteredClaims::EXPIRATION_TIME:
                    $builder->expiresAt(\DateTimeImmutable::createFromFormat('U', $value));
                    break;
                case RegisteredClaims::NOT_BEFORE:
                    $builder->canOnlyBeUsedAfter(\DateTimeImmutable::createFromFormat('U', $value));
                    break;
                case RegisteredClaims::ISSUED_AT:
                    $builder->issuedAt(\DateTimeImmutable::createFromFormat('U', $value));
                    break;
                case RegisteredClaims::ISSUER:
                    $builder->issuedBy($value);
                    break;
                case RegisteredClaims::AUDIENCE:
                    $builder->permittedFor($value);
                    break;
                case RegisteredClaims::SUBJECT:
                    $builder->relatedTo($value);
                    break;
                default:
                    $builder->withClaim($key, $value);
            }
        }
        return $builder;
    }

    /**
     * Decode a JSON Web Token.
     *
     * @param $token
     * @return array
     * @throws TokenInvalidException
     */
    public function decode($token)
    {
        try {
            /** @var \Lcobucci\JWT\Token\Plain */
            $token = $this->config->parser()->parse($token);
        } catch (Exception $e) {
            throw new TokenInvalidException('Could not decode token: ' . $e->getMessage(), $e->getCode(), $e);
        }

        if (!$this->config->validator()->validate($token, ...$this->config->validationConstraints())) {
            throw new TokenInvalidException('Token Signature could not be verified.');
        }
        return (new Collection($token->claims()->all()))
            ->map(function ($claim) {
                if (is_a($claim, \DateTimeImmutable::class)) {
                    return $claim->getTimestamp();
                }
                return is_object($claim) && method_exists($claim, 'getValue')
                    ? $claim->getValue()
                    : $claim;
            })
         ->toArray();
    }

    /**
     * Get the signer instance.
     *
     * @return \Lcobucci\JWT\Signer
     */
    protected function getSigner()
    {
        if (!array_key_exists($this->algo, $this->signers)) {
            throw new JWTException('The given algorithm could not be found');
        }

        return new $this->signers[$this->algo];
    }


    protected function isAsymmetric()
    {
        $reflect = new ReflectionClass($this->signer);

        return $reflect->isSubclassOf(Rsa::class) || $reflect->isSubclassOf(Ecdsa::class);
    }

    protected function getSigningKey()
    {
        return $this->isAsymmetric() ?
            InMemory::plainText($this->getPrivateKey(), $this->getPassphrase() ?? '') :
            InMemory::plainText($this->getSecret());
    }

    protected function getVerificationKey()
    {
        return $this->isAsymmetric() ?
            InMemory::plainText($this->getPublicKey()) :
            InMemory::plainText($this->getSecret());
    }


    protected function getSign()
    {
        if (!isset($this->signers[$this->algo])) {
            throw new JWTException('Cloud not find ' . $this->algo . ' algo');
        }
        return new $this->signers[$this->algo];
    }
}
