<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography\Algorithms\Eddsa;

use MiladRahimi\Jwt\Cryptography\Keys\Ed448PrivateKey;
use MiladRahimi\Jwt\Cryptography\Signer;
use MiladRahimi\Jwt\Exceptions\SigningException;

/**
 * Signs tokens with `Ed448` (RFC 9864), EdDSA over Curve448, via OpenSSL. Requires PHP 8.4 or later;
 * `Ed448PrivateKey` enforces that at construction.
 */
class Ed448Signer implements Signer
{
    protected static string $name = 'Ed448';

    protected Ed448PrivateKey $privateKey;

    public function __construct(Ed448PrivateKey $privateKey)
    {
        $this->privateKey = $privateKey;
    }

    /**
     * {@inheritDoc}
     */
    public function sign(string $message): string
    {
        $signature = '';

        // EdDSA hashes internally, so no digest algorithm (`0`) is passed to OpenSSL.
        if (
            openssl_sign($message, $signature, $this->privateKey->getResource(), 0) === true
            && is_string($signature)
        ) {
            return $signature;
        }

        throw new SigningException(openssl_error_string() ?: 'OpenSSL cannot sign the token.');
    }

    /**
     * {@inheritDoc}
     */
    public function name(): string
    {
        return static::$name;
    }

    /**
     * {@inheritDoc}
     */
    public function kid(): ?string
    {
        return $this->privateKey->getId();
    }

    public function getPrivateKey(): Ed448PrivateKey
    {
        return $this->privateKey;
    }
}
