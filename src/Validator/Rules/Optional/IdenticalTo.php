<?php
/**
 * Created by PhpStorm.
 * User: Milad Rahimi <info@miladrahimi.com>
 * Date: 5/16/2018 AD
 * Time: 00:42
 */

namespace MiladRahimi\Jwt\Validator\Rules\Optional;

use MiladRahimi\Jwt\Validator\Rule;

class IdenticalTo implements Rule
{
    /**
     * @var mixed
     */
    private $expectedValueAndType;

    /**
     * @param mixed $expectedValueAndType
     */
    public function __construct($expectedValueAndType)
    {
        $this->expectedValueAndType = $expectedValueAndType;
    }

    /**
     * @inheritdoc
     */
    public function check($value, bool $exists): bool
    {
        return $exists == false || $this->expectedValueAndType === $value;
    }
}