<?php
/**
 * Created by PhpStorm.
 * User: Milad Rahimi <info@miladrahimi.com>
 * Date: 6/1/2018 AD
 * Time: 21:49
 */

namespace MiladRahimi\Jwt\Cryptography\Algorithms\Rsa;

trait Naming
{
    /**
     * @var string
     */
    protected $name;

    /**
     * @inheritdoc
     */
    public function getName(): string
    {
        return $this->name;
    }

    /**
     * @return int
     */
    protected function algorithmName()
    {
        $table = [
            'RS256' => OPENSSL_ALGO_SHA256,
            'RS384' => OPENSSL_ALGO_SHA384,
            'RS512' => OPENSSL_ALGO_SHA512,
        ];

        return $table[$this->name];
    }
}