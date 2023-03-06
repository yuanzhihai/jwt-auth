<?php

namespace thans\jwt;

use thans\jwt\contract\JWTSubject;
use thans\jwt\exception\JWTException;
use thans\jwt\exception\UserNotDefinedException;
use think\Request;
use yzh52521\auth\credentials\BaseCredentials;
use yzh52521\auth\credentials\PasswordCredential;
use yzh52521\auth\interfaces\Guard;
use yzh52521\auth\interfaces\Provider;
use yzh52521\auth\traits\GuardHelpers;

class JWTGuard implements Guard
{
    use GuardHelpers;

    protected $jwt;

    protected $request;

    public function __construct(\thans\jwt\JWT $jwt,Provider $provider,Request $request)
    {
        $this->jwt      = $jwt;
        $this->provider = $provider;
        $this->request  = $request;
    }

    public function user()
    {
        if ($this->user !== null) {
            return $this->user;
        }

        if ($this->jwt->setRequest( $this->request )->getToken() &&
            ( $payload = $this->jwt->check( true ) ) &&
            $this->validateSubject()
        ) {
            return $this->user = $this->provider->retrieveById( $payload->get( 'uid' ) );
        }
    }

    public function userOrFail()
    {
        if (!$user = $this->user()) {
            throw new UserNotDefinedException;
        }

        return $user;
    }

    public function auth($credentials)
    {
        return (bool)$this->attempt( $credentials,false );
    }

    public function attempt(array $credentials = [],$login = true)
    {
        if (!$credentials instanceof BaseCredentials) {
            $credentials = PasswordCredential::fromArray( $credentials );
        }
        if ($this->validate( $credentials )) {
            return $login ? $this->login( $this->lastValidated ) : true;
        }
    }

    public function login(JWTSubject $user)
    {
        $token = $this->jwt->fromUser( $user );

        $this->setToken( $token )->setUser( $user );

        return $token;
    }

    public function logout()
    {
        $this->invalidate();

        $this->user = null;
        $this->jwt->unsetToken();
    }

    public function refresh()
    {
        return $this->jwt->refresh();
    }

    public function invalidate()
    {
        return $this->jwt->invalidate( $this->jwt->getToken() );
    }

    /**
     * @param $id
     * @return string
     */
    public function tokenById($id)
    {
        if ($user = $this->provider->retrieveById( $id )) {
            return $this->jwt->fromUser( $user );
        }
    }

    public function onceUsingId($id)
    {
        if ($user = $this->provider->retrieveById( $id )) {
            $this->setUser( $user );

            return true;
        }

        return false;
    }

    public function byId($id)
    {
        return $this->onceUsingId( $id );
    }

    public function getProvider()
    {
        return $this->provider;
    }

    public function setProvider(Provider $provider)
    {
        $this->provider = $provider;

        return $this;
    }

    public function getUser()
    {
        return $this->user;
    }

    /**
     * @return \thans\jwt\Payload
     */
    public function getPayload()
    {
        return $this->requireToken()->getPayload();
    }

    /**
     * Alias for getPayload().
     */
    public function payload()
    {
        return $this->getPayload();
    }


    public function setToken($token)
    {
        $this->jwt->setToken( $token );

        return $this;
    }

    protected function requireToken()
    {
        if (!$this->jwt->setRequest( $this->request )->getToken()) {
            throw new JWTException( 'Token could not be parsed from the request.' );
        }

        return $this->jwt;
    }


    protected function validateSubject()
    {
        if (!method_exists( $this->provider,'getModel' )) {
            return true;
        }

        return $this->jwt->checkSubjectModel( $this->provider->getModel() );
    }
}