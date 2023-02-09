<?php

use thans\jwt\command\SecretCommand;
use thans\jwt\provider\JWT as JWTProvider;
use think\facade\Console;
use think\App;

if (App::VERSION <= '6.0.0') {
    Console::addCommands( [
        SecretCommand::class
    ] );
    ( new JWTProvider( app( 'request' ) ) )->init();
}
