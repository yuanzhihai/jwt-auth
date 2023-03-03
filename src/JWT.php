<?php

namespace thans\jwt;

use thans\jwt\exception\BadMethodCallException;
use thans\jwt\parser\Parser;
use thans\jwt\exception\JWTException;
use think\Request;

use thans\jwt\contract\JWTSubject;

class JWT
{
    protected $token;

    public function parser()
    {
        return $this->parser;
    }

    public function __construct(protected Manager $manager,protected Parser $parser)
    {
    }

    public function createToken($customerClaim = [])
    {
        return $this->manager->encode( $customerClaim )->get();
    }

    public function check($getPayload = false)
    {
        try {
            $payload = $this->getPayload();
        } catch ( JWTException $e ) {
            return false;
        }

        return $getPayload ? $payload : true;
    }

    public function parseToken()
    {
        if (!$token = $this->parser->parseToken()) {
            throw new JWTException( 'No token is this request.' );
        }
        $this->setToken( $token );

        return $this;
    }

    public function getToken()
    {
        if ($this->token === null) {
            try {
                $this->parseToken();
            } catch ( JWTException $e ) {
                $this->token = null;
            }
        }

        return $this->token;
    }

    public function setToken($token)
    {
        $this->token = $token instanceof Token ? $token : new Token( $token );

        return $this;
    }

    /**
     * Unset the current token.
     *
     * @return $this
     */
    public function unsetToken()
    {
        $this->token = null;

        return $this;
    }

    public function requireToken()
    {
        $this->getToken();

        if (!$this->token) {
            throw new JWTException( 'Must have token' );
        }
    }

    public function payload()
    {
        return $this->getPayload();
    }

    public function getClaim($claim)
    {
        return $this->payload()->get( $claim );
    }


    public function fromSubject(JWTSubject $subject)
    {
        $customerClaim['uid'] = $subject->getJWTIdentifier();

        return $this->manager->encode( $customerClaim )->get();
    }

    public function fromUser(JWTSubject $user)
    {
        return $this->fromSubject( $user );
    }

    /**
     * 获取Payload
     * @return Payload
     * @throws JWTException
     * @throws exception\TokenBlacklistException
     */
    public function getPayload()
    {
        $this->requireToken();

        return $this->manager->decode( $this->token );
    }

    /**
     * 刷新Token
     * @return mixed
     * @throws JWTException
     */
    public function refresh()
    {
        $this->parseToken();

        return $this->manager->refresh( $this->token )->get();
    }


    /**
     * Hash the subject model and return it.
     *
     * @param string|object $model
     * @return string
     */
    protected function hashSubjectModel($model)
    {
        return sha1( is_object( $model ) ? get_class( $model ) : $model );
    }

    /**
     * Check if the subject model matches the one saved in the token.
     *
     * @param string|object $model
     * @return bool
     */
    public function checkSubjectModel($model)
    {
        if (( $prv = $this->payload()->get( 'prv' ) ) === null) {
            return true;
        }

        return $this->hashSubjectModel( $model ) === $prv;
    }


    public function setRequest(Request $request)
    {
        $this->parser->setRequest( $request );

        return $this;
    }


    public function __call($method,$parameters)
    {
        if (method_exists( $this->manager,$method )) {
            return call_user_func_array( [$this->manager,$method],$parameters );
        }

        throw new BadMethodCallException( "Method [$method] does not exist." );
    }
}
