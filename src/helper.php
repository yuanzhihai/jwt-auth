<?php

use thans\jwt\command\SecretCommand;
use thans\jwt\provider\JWT as JWTProvider;
use think\facade\Console;
use think\App;

if (strpos(App::VERSION, '6') === false) {
    Console::addCommands([
        SecretCommand::class
    ]);
    (new JWTProvider(app('request')))->init();
}
