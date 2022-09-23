<?php

namespace thans\jwt\claim;

use thans\jwt\exception\TokenExpiredException;

class Expiration extends Claim
{
    use DatetimeTrait;

    protected $name = 'exp';

    public function validatePayload()
    {
        if ($this->isPast($this->getValue())) {
            throw new TokenExpiredException('The token is expired.');
        }
    }
}
