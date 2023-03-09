<?php


namespace thans\jwt;

use thans\jwt\command\SecretCommand;
use thans\jwt\guard\Jwt;
use thans\jwt\middleware\InjectJwt;

class Service extends \think\Service
{
    public function boot()
    {
        $this->commands( SecretCommand::class );
        $this->app->middleware->add( InjectJwt::class );

        if ($this->app->has( 'auth' )) {
            $this->app->get( 'auth' )->extend( 'jwt',function ($app,$name,array $config) {
                return new JWTGuard(
                    $this->app->get( 'thans.jwt' ),
                    $this->app->get( 'auth' )->createUserProvider( $config['provider'] ),
                    $this->app->request
                );
            } );
        }
    }

    public function register()
    {
        $this->app->bind( 'thans.jwt',\thans\jwt\JWT::class );
        $this->app->bind( 'thans.jwt.auth',\thans\jwt\JWTAuth::class );
    }
}
