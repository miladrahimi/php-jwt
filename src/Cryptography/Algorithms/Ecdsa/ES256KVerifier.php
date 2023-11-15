<?php declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography\Algorithms\Ecdsa;

use MiladRahimi\Jwt\Cryptography\Keys\EcdsaPublicKey;
use MiladRahimi\Jwt\Exceptions\InvalidSignatureException;

class ES256KVerifier extends AbstractEcdsaVerifier
{
    protected static string $name = 'ES256K';

    protected EcdsaPublicKey $publicKey;

    public function __construct(EcdsaPublicKey $key)
    {
        $this->setPublicKey($key);
    }

    /**
     * @inheritdoc
     */
    public function verify(string $plain, string $signature): void
    {
        $signature = $this->signatureToDer($signature);
        if (openssl_verify($plain, $signature, $this->publicKey->getResource(), $this->algorithm()) !== 1) {
            throw new InvalidSignatureException(openssl_error_string() ?: "The signature is invalid.");
        }

        $this->publicKey->close();
    }

    public function getPublicKey(): EcdsaPublicKey
    {
        return $this->publicKey;
    }

    public function setPublicKey(EcdsaPublicKey $publicKey)
    {
        $this->publicKey = $publicKey;
    }
}
