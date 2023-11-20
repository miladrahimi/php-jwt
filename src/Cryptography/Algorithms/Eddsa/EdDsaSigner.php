<?php declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography\Algorithms\Eddsa;

use MiladRahimi\Jwt\Cryptography\Signer;
use MiladRahimi\Jwt\Exceptions\SigningException;
use RuntimeException;
use SodiumException;
use function function_exists;

class EdDsaSigner implements Signer
{
    protected static string $name = 'EdDSA';

    protected string $privateKey;

    protected ?string $kid;

    public function __construct(string $privateKey, ?string $kid = null)
    {
        $this->privateKey = $privateKey;
        $this->kid = $kid;
    }

    /**
     * @inheritdoc
     */
    public function sign(string $message): string
    {
        if (function_exists('sodium_crypto_sign_detached')) {
            try {
                return sodium_crypto_sign_detached($message, $this->privateKey);
            } catch (SodiumException $e) {
                throw new SigningException("Cannot sign using Sodium extension", 0, $e);
            }
        }

        throw new RuntimeException('The sodium_crypto_sign_detached function is not available');
    }

    public function name(): string
    {
        return static::$name;
    }

    public function kid(): ?string
    {
        return $this->kid;
    }

    public function getPrivateKey(): string
    {
        return $this->privateKey;
    }
}
