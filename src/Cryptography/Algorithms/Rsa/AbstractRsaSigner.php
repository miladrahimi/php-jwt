<?php

namespace MiladRahimi\Jwt\Cryptography\Algorithms\Rsa;

use MiladRahimi\Jwt\Cryptography\Keys\PrivateKey;
use MiladRahimi\Jwt\Cryptography\Signer;
use MiladRahimi\Jwt\Exceptions\SigningException;

/**
 * Class AbstractRsaSigner
 *
 * @package MiladRahimi\Jwt\Cryptography\Algorithms\Rsa
 */
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
    public function sign(string $message): string
    {
        $signature = '';

        if (openssl_sign($message, $signature, $this->privateKey->getResource(), $this->algorithmName()) === true) {
            return $signature;
        }

        throw new SigningException();
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
