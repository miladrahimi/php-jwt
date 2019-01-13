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
     * @var PrivateKey  Encryption key
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
    public function sign(string $plain): string
    {
        $signature = '';

        if (openssl_sign($plain, $signature, $this->privateKey->getResource(), $this->algorithmName()) === true) {
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
