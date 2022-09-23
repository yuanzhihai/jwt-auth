<?php

namespace thans\jwt\claim;

use DateInterval;
use DateTimeInterface;
use thans\jwt\exception\TokenInvalidException;
use thans\jwt\support\Utils;

trait DatetimeTrait
{
    /**
     * Time leeway in seconds.
     *
     * @var int
     */
    protected $leeway = 0;

    /**
     * Set the claim value, and call a validate method.
     *
     * @param mixed $value
     *
     * @return $this
     *
     */
    public function setValue($value)
    {
        if ($value instanceof DateInterval) {
            $value = Utils::now()->add($value);
        }

        if ($value instanceof DateTimeInterface) {
            $value = $value->getTimestamp();
        }

        return parent::setValue($value);
    }

    /**
     * {@inheritdoc}
     */
    public function validateCreate($value)
    {
        if (!is_numeric($value)) {
            throw new TokenInvalidException($this);
        }

        return $value;
    }

    /**
     * Determine whether the value is in the future.
     *
     * @param mixed $value
     *
     * @return bool
     */
    protected function isFuture($value)
    {
        return Utils::isFuture($value, $this->leeway);
    }

    /**
     * Determine whether the value is in the past.
     *
     * @param mixed $value
     *
     * @return bool
     */
    protected function isPast($value)
    {
        return Utils::isPast($value, $this->leeway);
    }

    /**
     * Set the leeway in seconds.
     *
     * @param int $leeway
     *
     * @return $this
     */
    public function setLeeway($leeway)
    {
        $this->leeway = $leeway;

        return $this;
    }
}