<?php declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography\Algorithms\Eddsa;

use MiladRahimi\Jwt\Base64\Base64Parser;
use MiladRahimi\Jwt\Base64\SafeBase64Parser;
use MiladRahimi\Jwt\Cryptography\Verifier;
use MiladRahimi\Jwt\Exceptions\InvalidSignatureException;
use RuntimeException;
use SodiumException;

class EdDsaVerifier implements Verifier
{
    protected static string $name = 'EdDSA';

    protected string $publicKey;

    public function __construct(string $key)
    {
        $this->publicKey = $key;
    }

    /**
     * @inheritdoc
     */
    public function verify(string $plain, string $signature): void
    {
        if (function_exists('sodium_crypto_sign_verify_detached')) {
            try {
                if (!sodium_crypto_sign_verify_detached($signature, $plain, $this->publicKey)) {
                    throw new InvalidSignatureException('Signature is to verified');
                }
            } catch (SodiumException $e) {
                throw new InvalidSignatureException('Sodium cannot verify the signature', 0, $e);
            }
        } else {
            throw new RuntimeException('sodium_crypto_sign_verify_detached function is not available');
        }
    }

    public function name(): string
    {
        return static::$name;
    }

    public function getPublicKey(): string
    {
        return $this->publicKey;
    }
}
