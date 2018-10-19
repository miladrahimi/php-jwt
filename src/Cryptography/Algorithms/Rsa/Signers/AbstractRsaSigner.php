<?php
/**
 * Created by PhpStorm.
 * User: Milad Rahimi <info@miladrahimi.com>
 * Date: 5/14/2018 AD
 * Time: 22:23
 */

namespace MiladRahimi\Jwt\Cryptography\Algorithms\Rsa\Signers;

use MiladRahimi\Jwt\Cryptography\Algorithms\Rsa\Naming;
use MiladRahimi\Jwt\Cryptography\Keys\PrivateKey;
use MiladRahimi\Jwt\Cryptography\Signer;

abstract class AbstractRsaSigner implements Signer
{
    use Naming;

    /**
     * @var PrivateKey
     */
    protected $privateKey;

    /**
     * AbstractRsaSigner constructor.
     *
     * @param PrivateKey $publicKey
     */
    public function __construct(PrivateKey $publicKey)
    {
        $this->setPrivateKey($publicKey);
    }

    /**
     * @inheritdoc
     */
    public function sign(string $data): string
    {
        $signature = '';

        openssl_sign($data, $signature, $this->privateKey->getResource(), $this->algorithmName());

        return $signature;
    }

    /**
     * @return PrivateKey
     */
    public function getPrivateKey(): PrivateKey
    {
        return $this->privateKey;
    }

    /**
     * @param PrivateKey $privateKey
     */
    public function setPrivateKey(PrivateKey $privateKey)
    {
        $this->privateKey = $privateKey;
    }
}