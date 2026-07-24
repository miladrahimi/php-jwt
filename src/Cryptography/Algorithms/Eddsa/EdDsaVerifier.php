<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography\Algorithms\Eddsa;

use MiladRahimi\Jwt\Cryptography\Keys\EdDsaPublicKey;
use MiladRahimi\Jwt\Cryptography\NamedVerifier;
use MiladRahimi\Jwt\Exceptions\InvalidSignatureException;
use RuntimeException;
use SodiumException;

class EdDsaVerifier implements NamedVerifier
{
    protected static string $name = 'EdDSA';

    protected EdDsaPublicKey $publicKey;

    public function __construct(EdDsaPublicKey $publicKey)
    {
        $this->publicKey = $publicKey;
    }

    /**
     * {@inheritDoc}
     */
    public function verify(string $plain, string $signature): void
    {
        if ($signature === '') {
            throw new InvalidSignatureException('The signature is not valid.');
        }

        if (function_exists('sodium_crypto_sign_verify_detached')) {
            try {
                if (!sodium_crypto_sign_verify_detached($signature, $plain, $this->publicKey->getContent())) {
                    throw new InvalidSignatureException('The signature is invalid.');
                }
            } catch (SodiumException $e) {
                throw new InvalidSignatureException('Sodium cannot verify the signature.', 0, $e);
            }
        } else {
            // @codeCoverageIgnoreStart
            throw new RuntimeException('The sodium_crypto_sign_verify_detached function is not available.');
            // @codeCoverageIgnoreEnd
        }
    }

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

    public function getPublicKey(): EdDsaPublicKey
    {
        return $this->publicKey;
    }
}
