<?php


namespace thans\jwt;

use thans\jwt\claim\Factory;
use thans\jwt\claim\Issuer;
use thans\jwt\claim\Audience;
use thans\jwt\claim\Expiration;
use thans\jwt\claim\IssuedAt;
use thans\jwt\claim\JwtId;
use thans\jwt\claim\NotBefore;
use thans\jwt\claim\Subject;
use think\helper\Arr;

class Payload
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


    public function __construct(protected Factory $factory)
    {
    }

    public function customer(array $claim = [])
    {
        foreach ( $claim as $key => $value ) {
            $this->factory->customer(
                $key,
                is_object( $value ) ? $value->getValue() : $value
            );
        }

        return $this;
    }

    public function get($claim = null)
    {
        $claim = value( $claim );

        if ($claim !== null) {
            if (is_array( $claim )) {
                return array_map( [$this,'get'],$claim );
            }

            return Arr::get( $this->toArray(),$claim );
        }

        return $this->toArray();
    }


    public function check($refresh = false)
    {
        $this->factory->validate( $refresh );

        return $this;
    }

    public function toArray()
    {
        return ( new \think\Collection( $this->factory->builder()->getClaims() ) )->map( function ($item) {
            return $item->getValue();
        } )->toArray();
    }
}
