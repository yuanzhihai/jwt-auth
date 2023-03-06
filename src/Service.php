<?php


namespace thans\jwt;

use thans\jwt\command\SecretCommand;
use thans\jwt\middleware\InjectJwt;

class Service extends \think\Service
{
    public function boot()
    {
        $this->commands( SecretCommand::class );
        $this->app->middleware->add( InjectJwt::class );

        \yzh52521\facade\Auth::extend( 'jwt',function ($app,$name,array $config) {
            return new JWTGuard(
                $this->app->get( 'thans.jwt' ),
                \yzh52521\facade\Auth::createUserProvider( $config['provider'] ),
                $this->app->request
            );
        } );
    }

    public function register()
    {
        $this->app->bind( 'thans.jwt',\thans\jwt\JWT::class );
    }
}
