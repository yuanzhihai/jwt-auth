<?php

namespace thans\jwt\provider\JWT;


use thans\jwt\exception\JWTException;

abstract class Provider
{
    protected $secret;

    protected $algo;

    protected $keys;

    public function getPublicKey()
    {
        if (is_file( $this->keys['public'] )) {
            return $this->keys['public'];
        }

        throw new JWTException( 'Please set public key as the path of pem file.' );
    }

    public function getPrivateKey()
    {
        if (is_file( $this->keys['private'] )) {
            return $this->keys['private'];
        }
        throw new JWTException( 'Please set private key as the path of pem file.' );
    }

    /**
     * Set the algorithm used to sign the token.
     *
     * @param string $algo
     * @return $this
     */
    public function setAlgo($algo)
    {
        $this->algo = $algo;

        return $this;
    }

    /**
     * Get the algorithm used to sign the token.
     *
     * @return string
     */
    public function getAlgo()
    {
        return $this->algo;
    }

    /**
     * Get the array of keys used to sign tokens
     * with an asymmetric algorithm.
     *
     * @return array
     */
    public function getKeys()
    {
        return $this->keys;
    }


    /**
     * Set the keys used to sign the token.
     *
     * @param array $keys
     * @return $this
     */
    public function setKeys(array $keys)
    {
        $this->keys = $keys;

        return $this;
    }

    /**
     * Set the secret used to sign the token.
     *
     * @param string $secret
     * @return $this
     */
    public function setSecret($secret)
    {
        $this->secret = $secret;

        return $this;
    }

    public function getSecret()
    {
        return $this->secret;
    }

    public function getPassphrase()
    {
        return $this->keys['passphrase'];
    }

    /**
     * Get the key used to sign the tokens.
     *
     * @return string|null
     */
    protected function getSigningKey()
    {
        return $this->isAsymmetric() ? $this->getPrivateKey() : $this->getSecret();
    }

    /**
     * Get the key used to verify the tokens.
     *
     * @return string|null
     */
    protected function getVerificationKey()
    {
        return $this->isAsymmetric() ? $this->getPublicKey() : $this->getSecret();
    }

    abstract protected function isAsymmetric();
}
