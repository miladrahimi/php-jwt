<?php

namespace MiladRahimi\Jwt\Cryptography\Algorithms\Rsa;

use MiladRahimi\Jwt\Cryptography\Keys\RsaPrivateKey;
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
     * @var RsaPrivateKey
     */
    protected $privateKey;

    /**
     * AbstractRsaSigner constructor.
     *
     * @param RsaPrivateKey $publicKey
     */
    public function __construct(RsaPrivateKey $publicKey)
    {
        $this->setPrivateKey($publicKey);
    }

    /**
     * @inheritdoc
     */
    public function sign(string $message): string
    {
        $signature = '';

        if (openssl_sign($message, $signature, $this->privateKey->getResource(), $this->algorithm()) === true) {
            $this->privateKey->close();

            return $signature;
        }

        throw new SigningException();
    }

    /**
     * @return RsaPrivateKey
     */
    public function getPrivateKey(): RsaPrivateKey
    {
        return $this->privateKey;
    }

    /**
     * @param RsaPrivateKey $privateKey
     */
    public function setPrivateKey(RsaPrivateKey $privateKey)
    {
        $this->privateKey = $privateKey;
    }
}
