<?php

namespace thans\jwt\command;

use think\console\Input;
use think\console\Output;

class SecretCommand extends \think\console\Command
{
    public function configure()
    {
        $this->setName( 'jwt:create' )
            ->setDescription( 'create jwt secret and create config file' );
    }

    public function execute(Input $input,Output $output)
    {
        $key  = md5( uniqid().time().rand( 0,60 ) );
        $path = app()->getAppPath().'..'.DIRECTORY_SEPARATOR.'.env';
        if (file_exists( $path )
            && strpos( file_get_contents( $path ),'[JWT]' )
        ) {
            $output->writeln( 'JWT_SECRET is exists' );
        } else {
            file_put_contents(
                $path,
                PHP_EOL."[JWT]".PHP_EOL."SECRET=$key".PHP_EOL,
                FILE_APPEND
            );
            $output->writeln( 'JWT_SECRET has created' );
        }
        $this->createConfig( $output );
    }

    public function createConfig($output)
    {
        $configFilePath = app()->getAppPath().'..'.DIRECTORY_SEPARATOR.'config'
            .DIRECTORY_SEPARATOR.'jwt.php';

        if (is_file( $configFilePath )) {
            $output->writeln( 'Config file is exist' );

            return;
        }
        $res = copy( __DIR__.DIRECTORY_SEPARATOR.'..'.DIRECTORY_SEPARATOR.'..'
            .DIRECTORY_SEPARATOR.'config'.DIRECTORY_SEPARATOR
            .'config.php',$configFilePath );
        if ($res) {
            $output->writeln( 'Create config file success:'.$configFilePath );
        } else {
            $output->writeln( 'Create config file error' );
        }
    }
}
