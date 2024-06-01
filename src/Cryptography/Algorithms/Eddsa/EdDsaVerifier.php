<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography\Algorithms\Eddsa;

use MiladRahimi\Jwt\Cryptography\Keys\EdDsaPublicKey;
use MiladRahimi\Jwt\Cryptography\Verifier;
use MiladRahimi\Jwt\Exceptions\InvalidSignatureException;
use RuntimeException;
use SodiumException;

class EdDsaVerifier implements Verifier
{
    protected static string $name = 'EdDSA';

    protected EdDsaPublicKey $publicKey;

    public function __construct(EdDsaPublicKey $publicKey)
    {
        $this->publicKey = $publicKey;
    }

    /**
     * @inheritdoc
     */
    public function verify(string $plain, string $signature): void
    {
        if (function_exists('sodium_crypto_sign_verify_detached')) {
            try {
                if (!sodium_crypto_sign_verify_detached($signature, $plain, $this->publicKey->getContent())) {
                    throw new InvalidSignatureException('Signature is to verified.');
                }
            } catch (SodiumException $e) {
                throw new InvalidSignatureException('Sodium cannot verify the signature.', 0, $e);
            }
        } else {
            throw new RuntimeException('sodium_crypto_sign_verify_detached function is not available.');
        }
    }

    public function name(): string
    {
        return static::$name;
    }

    /**
     * @inheritDoc
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
