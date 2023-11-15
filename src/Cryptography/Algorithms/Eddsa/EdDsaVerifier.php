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

    protected Base64Parser $base64Parser;


    public function __construct(string $key, ?Base64Parser $base64Parser = null)
    {
        if (!function_exists('sodium_crypto_sign_detached')) {
            throw new RuntimeException('sodium_crypto_sign_detached function is not available');
        }

        $this->setPublicKey($key);
        $this->setBase64Parser($base64Parser ?: new SafeBase64Parser());
    }

    /**
     * @inheritdoc
     */
    public function verify(string $plain, string $signature): void
    {
        if (function_exists('sodium_crypto_sign_verify_detached')) {
            $key = $this->base64Parser->decode($this->publicKey);
            try {
                if (!sodium_crypto_sign_verify_detached($signature, $plain, $key)) {
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

    public function setPublicKey(string $publicKey)
    {
        $this->publicKey = $publicKey;
    }

    public function getBase64Parser(): Base64Parser
    {
        return $this->base64Parser;
    }

    public function setBase64Parser(Base64Parser $base64Parser): void
    {
        $this->base64Parser = $base64Parser;
    }
}
