<?php

namespace MiladRahimi\Jwt\Cryptography\Algorithms\Rsa;

use MiladRahimi\Jwt\Cryptography\Keys\RsaPublicKey;
use MiladRahimi\Jwt\Cryptography\Verifier;
use MiladRahimi\Jwt\Exceptions\InvalidSignatureException;

/**
 * Class AbstractRsaVerifier
 *
 * @package MiladRahimi\Jwt\Cryptography\Algorithms\Rsa
 */
abstract class AbstractRsaVerifier implements Verifier
{
    use Naming;

    /**
     * @var RsaPublicKey
     */
    protected $publicKey;

    /**
     * AbstractRsaVerifier constructor.
     *
     * @param RsaPublicKey $key
     */
    public function __construct(RsaPublicKey $key)
    {
        $this->setPublicKey($key);
    }

    /**
     * @inheritdoc
     */
    public function verify(string $plain, string $signature)
    {
        if (openssl_verify($plain, $signature, $this->publicKey->getResource(), $this->algorithm()) !== 1) {
            throw new InvalidSignatureException();
        }

        $this->publicKey->close();
    }

    /**
     * @return RsaPublicKey
     */
    public function getPublicKey(): RsaPublicKey
    {
        return $this->publicKey;
    }

    /**
     * @param RsaPublicKey $publicKey
     */
    public function setPublicKey(RsaPublicKey $publicKey)
    {
        $this->publicKey = $publicKey;
    }
}
