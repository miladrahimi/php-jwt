<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography\Algorithms\Rsa;

use MiladRahimi\Jwt\Cryptography\Keys\RsaPrivateKey;
use MiladRahimi\Jwt\Cryptography\Signer;
use MiladRahimi\Jwt\Exceptions\SigningException;

class AbstractRsaSigner implements Signer
{
    use Algorithm;

    protected RsaPrivateKey $privateKey;

    public function __construct(RsaPrivateKey $publicKey)
    {
        $this->privateKey = $publicKey;
    }

    /**
     * @inheritdoc
     */
    public function sign(string $message): string
    {
        $signature = '';

        if (openssl_sign($message, $signature, $this->privateKey->getResource(), $this->algorithm()) === true) {
            return $signature;
        }

        throw new SigningException(openssl_error_string() ?: "OpenSSL cannot sign the token.");
    }

    /**
     * @inheritDoc
     */
    public function kid(): ?string
    {
        return $this->privateKey->getId();
    }

    public function getPrivateKey(): RsaPrivateKey
    {
        return $this->privateKey;
    }
}
