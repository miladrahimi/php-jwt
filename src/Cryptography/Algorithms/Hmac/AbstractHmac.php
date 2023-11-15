<?php declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography\Algorithms\Hmac;

use MiladRahimi\Jwt\Cryptography\Signer;
use MiladRahimi\Jwt\Cryptography\Verifier;
use MiladRahimi\Jwt\Exceptions\InvalidKeyException;
use MiladRahimi\Jwt\Exceptions\InvalidSignatureException;
use MiladRahimi\Jwt\Exceptions\SigningException;
use ValueError;

abstract class AbstractHmac implements Signer, Verifier
{
    protected static string $name;

    protected string $key;

    public function __construct(string $key)
    {
        $this->key = $key;
    }

    /**
     * @inheritdoc
     */
    public function sign(string $message): string
    {
        try {
            if (strlen($this->key) < 32 || strlen($this->key) > 6144) {
                throw new InvalidKeyException('Key length must be between 32 and 6144');
            }
            return hash_hmac($this->algorithm(), $message, "$this->key", true);
        } catch (ValueError|InvalidKeyException $e) {
            throw new SigningException('Cannot sign the signature', 0, $e);
        }
    }

    /**
     * @inheritDoc
     */
    public function verify(string $plain, string $signature): void
    {
        if ($signature !== $this->sign($plain)) {
            throw new InvalidSignatureException();
        }
    }

    protected function algorithm(): string
    {
        return 'sha' . substr($this->name(), 2);
    }

    public function name(): string
    {
        return static::$name;
    }

    public function getKey(): string
    {
        return $this->key;
    }
}
