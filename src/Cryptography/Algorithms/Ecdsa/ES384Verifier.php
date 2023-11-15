<?php declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography\Algorithms\Ecdsa;

use MiladRahimi\Jwt\Cryptography\Keys\EcdsaPublicKey;
use MiladRahimi\Jwt\Exceptions\InvalidSignatureException;

class ES384Verifier extends AbstractEcdsaVerifier
{
    protected static string $name = 'ES384';

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
        $sig = $this->signatureToDer($signature);
        if (openssl_verify($plain, $sig, $this->publicKey->getResource(), $this->algorithm()) !== 1) {
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
