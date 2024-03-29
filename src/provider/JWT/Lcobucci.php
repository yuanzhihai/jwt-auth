<?php

namespace thans\jwt\provider\JWT;

use Exception;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Blake2b;
use Lcobucci\JWT\Signer\Ecdsa;
use Lcobucci\JWT\Signer\Ecdsa\Sha256 as ES256;
use Lcobucci\JWT\Signer\Ecdsa\Sha384 as ES384;
use Lcobucci\JWT\Signer\Ecdsa\Sha512 as ES512;
use Lcobucci\JWT\Signer\Eddsa;
use Lcobucci\JWT\Signer\Hmac\Sha256 as HS256;
use Lcobucci\JWT\Signer\Hmac\Sha384 as HS384;
use Lcobucci\JWT\Signer\Hmac\Sha512 as HS512;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa;
use Lcobucci\JWT\Signer\Rsa\Sha256 as RS256;
use Lcobucci\JWT\Signer\Rsa\Sha384 as RS384;
use Lcobucci\JWT\Signer\Rsa\Sha512 as RS512;
use Lcobucci\JWT\Token\RegisteredClaims;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use thans\jwt\exception\JWTException;
use thans\jwt\exception\TokenInvalidException;
use think\Collection;

class Lcobucci extends Provider
{
    protected $signers = [
        'HS256'   => HS256::class,
        'HS384'   => HS384::class,
        'HS512'   => HS512::class,
        'BLAKE2B' => BLAKE2B::class,
        'RS256'   => RS256::class,
        'RS384'   => RS384::class,
        'RS512'   => RS512::class,
        'ES256'   => ES256::class,
        'ES384'   => ES384::class,
        'ES512'   => ES512::class,
        'EDDSA'   => EdDSA::class,
    ];

    /** @var \Lcobucci\JWT\Signer The signer chosen based on the aglo. */
    protected $signer;

    protected $builder;

    public function __construct(protected $secret,protected $algo,array $keys,protected $config = null)
    {
        $this->keys   = $keys;
        $this->signer = $this->getSigner();
        $this->config = $config ?: $this->buildConfig();
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
        $this->builder = $this->getBuilderFromClaims( $payload );
        try {
            return $this->builder->getToken( $this->config->signer(),$this->config->signingKey() )->toString();
        } catch ( Exception $e ) {
            throw new JWTException( 'Could not create token: '.$e->getMessage(),$e->getCode(),$e );
        }
    }

    /**
     * Create an instance of the builder with all the claims applied.
     * Adds a claim to the {@see $config}.
     * @param array $payload
     * @return \Lcobucci\JWT\Token\Builder
     */
    protected function getBuilderFromClaims(array $payload): Builder
    {
        $builder = $this->config->builder();
        foreach ( $payload as $key => $value ) {
            $builder = match ( $key ) {
                RegisteredClaims::ID => $builder->identifiedBy( $value ),
                RegisteredClaims::EXPIRATION_TIME => $builder->expiresAt( \DateTimeImmutable::createFromFormat( 'U',$value ) ),
                RegisteredClaims::NOT_BEFORE => $builder->canOnlyBeUsedAfter( \DateTimeImmutable::createFromFormat( 'U',$value ) ),
                RegisteredClaims::ISSUED_AT => $builder->issuedAt( \DateTimeImmutable::createFromFormat( 'U',$value ) ),
                RegisteredClaims::ISSUER => $builder->issuedBy( $value ),
                RegisteredClaims::AUDIENCE => $builder->permittedFor( $value ),
                RegisteredClaims::SUBJECT => $builder->relatedTo( $value ),
                default => $builder->withClaim( $key,$value ),
            };
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
            $token = $this->config->parser()->parse( $token );
        } catch ( Exception $e ) {
            throw new TokenInvalidException( 'Could not decode token: '.$e->getMessage(),$e->getCode(),$e );
        }

        if (!$this->config->validator()->validate( $token,...$this->config->validationConstraints() )) {
            throw new TokenInvalidException( 'Token Signature could not be verified.' );
        }
        return ( new Collection( $token->claims()->all() ) )
            ->map( function ($claim) {
                if (is_a( $claim,\DateTimeImmutable::class )) {
                    return $claim->getTimestamp();
                }
                return is_object( $claim ) && method_exists( $claim,'getValue' )
                    ? $claim->getValue()
                    : $claim;
            } )
            ->toArray();
    }

    /**
     * @return Configuration
     * @throws JWTException
     */
    protected function buildConfig(): Configuration
    {
        $config = $this->isAsymmetric()
            ? Configuration::forAsymmetricSigner(
                $this->signer,
                $this->getSigningKey(),
                $this->getVerificationKey()
            )
            : Configuration::forSymmetricSigner( $this->signer,$this->getSigningKey() );

        $config->setValidationConstraints(
            new SignedWith( $this->signer,$this->getVerificationKey() )
        );

        return $config;
    }

    /**
     * Get the signer instance.
     *
     * @return \Lcobucci\JWT\Signer
     */
    protected function getSigner()
    {
        if (!array_key_exists( $this->algo,$this->signers )) {
            throw new JWTException( 'The given algorithm could not be found' );
        }

        return new $this->signers[$this->algo];
    }


    /**
     * {@inheritdoc}
     */
    protected function isAsymmetric()
    {
        return is_subclass_of( $this->signer,Rsa::class )
            || is_subclass_of( $this->signer,Ecdsa::class );
    }

    /**
     * @return Key
     * @throws JWTException
     */
    protected function getSigningKey()
    {
        if ($this->isAsymmetric()) {
            if (!$privateKey = $this->getPrivateKey()) {
                throw new JWTException( 'Private key is not set.' );
            }
            return $this->getKey( $privateKey,$this->getPassphrase() ?? '' );
        }

        if (!$secret = $this->getSecret()) {
            throw new JWTException( 'Secret is not set.' );
        }
        return $this->getKey( $secret );
    }

    /**
     * {@inheritdoc}
     *
     * @return Key
     * @throws JWTException
     */
    protected function getVerificationKey()
    {
        if ($this->isAsymmetric()) {
            if (!$public = $this->getPublicKey()) {
                throw new JWTException( 'Public key is not set.' );
            }

            return $this->getKey( $public );
        }

        if (!$secret = $this->getSecret()) {
            throw new JWTException( 'Secret is not set.' );
        }

        return $this->getKey( $secret );
    }

    protected function getSign()
    {
        if (!isset( $this->signers[$this->algo] )) {
            throw new JWTException( 'Cloud not find '.$this->algo.' algo' );
        }
        return new $this->signers[$this->algo];
    }

    /**
     * Get the signing key instance.
     */
    protected function getKey(string $contents,string $passphrase = ''): Key
    {
        return InMemory::plainText( $contents,$passphrase );
    }
}
