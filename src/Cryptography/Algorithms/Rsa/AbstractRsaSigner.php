<?php declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography\Algorithms\Rsa;

use MiladRahimi\Jwt\Cryptography\Keys\RsaPrivateKey;
use MiladRahimi\Jwt\Cryptography\Signer;
use MiladRahimi\Jwt\Exceptions\SigningException;

class AbstractRsaSigner implements Signer
{
    use Naming;

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
            $this->privateKey->close();
            return $signature;
        }

        throw new SigningException(openssl_error_string() ?: "OpenSSL cannot sign the token.");
    }

    public function getPrivateKey(): RsaPrivateKey
    {
        return $this->privateKey;
    }
}
