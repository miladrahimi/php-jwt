<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography\Algorithms\Hmac;

use Error;
use MiladRahimi\Jwt\Cryptography\Keys\HmacKey;
use MiladRahimi\Jwt\Cryptography\Signer;
use MiladRahimi\Jwt\Cryptography\Verifier;
use MiladRahimi\Jwt\Exceptions\InvalidKeyException;
use MiladRahimi\Jwt\Exceptions\InvalidSignatureException;
use MiladRahimi\Jwt\Exceptions\SigningException;

abstract class AbstractHmac implements Signer, Verifier
{
    protected static string $name;

    protected HmacKey $key;

    public function __construct(HmacKey $key)
    {
        $this->key = $key;
    }

    /**
     * {@inheritDoc}
     */
    public function sign(string $message): string
    {
        try {
            if (strlen($this->key->getContent()) < 32 || strlen($this->key->getContent()) > 6144) {
                throw new InvalidKeyException('Key length must be between 32 and 6144.');
            }
            return hash_hmac($this->algorithm(), $message, $this->key->getContent(), true);
        } catch (Error | InvalidKeyException $e) {
            throw new SigningException('Cannot sign the message.', 0, $e);
        }
    }

    /**
     * {@inheritDoc}
     */
    public function verify(string $plain, string $signature): void
    {
        if (!hash_equals($this->sign($plain), $signature)) {
            throw new InvalidSignatureException();
        }
    }

    /**
     * Derives the hashing algorithm name from the JWA name.
     */
    protected function algorithm(): string
    {
        return 'sha' . substr($this->name(), 2);
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
        return $this->key->getId();
    }

    public function getKey(): HmacKey
    {
        return $this->key;
    }
}
