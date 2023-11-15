<?php

namespace MiladRahimi\Jwt\Cryptography\Algorithms\Ecdsa;

use MiladRahimi\Jwt\Cryptography\Keys\EcdsaPrivateKey;
use MiladRahimi\Jwt\Exceptions\SigningException;

class ES256KSigner extends AbstractEcdsaSigner
{
    protected static string $name = 'ES256K';

    protected EcdsaPrivateKey $privateKey;

    public function __construct(EcdsaPrivateKey $privateKey)
    {
        $this->setPrivateKey($privateKey);
    }

    /**
     * @inheritdoc
     */
    public function sign(string $message): string
    {
        if (openssl_sign($message, $signature, $this->privateKey->getResource(), $this->algorithm()) === true) {
            $this->privateKey->close();

            return $this->derToSignature($signature, 256);
        }

        throw new SigningException(openssl_error_string() ?: "OpenSSL cannot sign the token.");
    }

    public function getPrivateKey(): EcdsaPrivateKey
    {
        return $this->privateKey;
    }

    public function setPrivateKey(EcdsaPrivateKey $privateKey)
    {
        $this->privateKey = $privateKey;
    }
}
