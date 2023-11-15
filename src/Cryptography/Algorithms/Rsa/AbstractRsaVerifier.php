<?php declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography\Algorithms\Rsa;

use MiladRahimi\Jwt\Cryptography\Keys\RsaPublicKey;
use MiladRahimi\Jwt\Cryptography\Verifier;
use MiladRahimi\Jwt\Exceptions\InvalidSignatureException;

class AbstractRsaVerifier implements Verifier
{
    use Naming;

    protected RsaPublicKey $publicKey;

    public function __construct(RsaPublicKey $key)
    {
        $this->publicKey = $key;
    }

    /**
     * @inheritdoc
     */
    public function verify(string $plain, string $signature): void
    {
        if (openssl_verify($plain, $signature, $this->publicKey->getResource(), $this->algorithm()) !== 1) {
            throw new InvalidSignatureException(openssl_error_string() ?: "The signature is invalid.");
        }

        $this->publicKey->close();
    }

    public function getPublicKey(): RsaPublicKey
    {
        return $this->publicKey;
    }
}
