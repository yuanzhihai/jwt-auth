<?php

namespace thans\jwt\claim;

use thans\jwt\exception\TokenExpiredException;
use thans\jwt\exception\TokenInvalidException;

class IssuedAt extends Claim
{
    use DatetimeTrait;

    protected $name = 'iat';

    public function validatePayload()
    {
        if ($this->isFuture($this->getValue())) {
            throw new TokenInvalidException('Issued At (iat) timestamp cannot be in the future');
        }
    }

    public function validateRefresh($refreshTtl)
    {
        if ($this->isPast($this->getValue() + $refreshTtl)) {
            throw new TokenExpiredException('Token has expired and can no longer be refreshed');
        }
    }
}
