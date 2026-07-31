<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography\Algorithms\Eddsa;

use MiladRahimi\Jwt\Cryptography\Keys\Ed448PublicKey;
use MiladRahimi\Jwt\Cryptography\NamedVerifier;
use MiladRahimi\Jwt\Exceptions\InvalidSignatureException;

/**
 * Verifies tokens signed with `Ed448` (RFC 9864), EdDSA over Curve448, via OpenSSL. Requires PHP 8.4 or
 * later; `Ed448PublicKey` enforces that at construction.
 */
class Ed448Verifier implements NamedVerifier
{
    protected static string $name = 'Ed448';

    protected Ed448PublicKey $publicKey;

    public function __construct(Ed448PublicKey $publicKey)
    {
        $this->publicKey = $publicKey;
    }

    /**
     * {@inheritDoc}
     */
    public function verify(string $plain, string $signature): void
    {
        // EdDSA hashes internally, so no digest algorithm (`0`) is passed to OpenSSL.
        if (openssl_verify($plain, $signature, $this->publicKey->getResource(), 0) !== 1) {
            throw new InvalidSignatureException(openssl_error_string() ?: 'The signature is not valid.');
        }
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
        return $this->publicKey->getId();
    }

    public function getPublicKey(): Ed448PublicKey
    {
        return $this->publicKey;
    }
}
