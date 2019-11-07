<?php

namespace MiladRahimi\Jwt\Cryptography\Algorithms\Rsa;

use MiladRahimi\Jwt\Cryptography\Keys\PublicKey;
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
     * @var PublicKey
     */
    protected $publicKey;

    /**
     * AbstractRsaVerifier constructor.
     *
     * @param PublicKey $key
     */
    public function __construct(PublicKey $key)
    {
        $this->setPublicKey($key);
    }

    /**
     * @inheritdoc
     */
    public function verify(string $plain, string $signature)
    {
        if (openssl_verify($plain, $signature, $this->publicKey->getResource(), $this->algorithmName()) !== 1) {
            throw new InvalidSignatureException();
        }
    }

    /**
     * @return PublicKey
     */
    public function getPublicKey(): PublicKey
    {
        return $this->publicKey;
    }

    /**
     * @param PublicKey $publicKey
     */
    public function setPublicKey(PublicKey $publicKey)
    {
        $this->publicKey = $publicKey;
    }
}
