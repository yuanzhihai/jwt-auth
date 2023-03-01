<?php


namespace thans\jwt\parser;

use think\Request;

class Parser
{

    public function __construct(protected Request $request,private $chain = [])
    {
    }

    public function setRequest(Request $request)
    {
        $this->request = $request;

        return $this;
    }

    public function setChain(array $chain)
    {
        $this->chain = $chain;

        return $this;
    }

    public function getChain()
    {
        return $this->chain;
    }

    public function parseToken()
    {
        foreach ( $this->chain as $parser ) {
            if ($response = $parser->parse( $this->request )) {
                return $response;
            }
        }
    }

    public function hasToken()
    {
        return $this->parseToken() !== null;
    }
}
