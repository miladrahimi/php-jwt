<?php declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography\Algorithms\Eddsa;

use MiladRahimi\Jwt\Base64\Base64Parser;
use MiladRahimi\Jwt\Base64\SafeBase64Parser;
use MiladRahimi\Jwt\Cryptography\Signer;
use MiladRahimi\Jwt\Exceptions\SigningException;
use RuntimeException;
use SodiumException;
use function function_exists;

class EdDsaSigner implements Signer
{
    protected static string $name = 'EdDSA';

    protected Base64Parser $base64Parser;

    protected string $privateKey;

    public function __construct(string $privateKey, ?Base64Parser $base64Parser = null)
    {
        $this->setPrivateKey($privateKey);
        $this->setBase64Parser($base64Parser ?: new SafeBase64Parser());
    }

    /**
     * @inheritdoc
     */
    public function sign(string $message): string
    {
        if (function_exists('sodium_crypto_sign_detached')) {
            try {
                return sodium_crypto_sign_detached($message, $this->base64Parser->decode($this->privateKey));
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

    public function getPrivateKey(): string
    {
        return $this->privateKey;
    }

    public function setPrivateKey(string $privateKey)
    {
        $this->privateKey = $privateKey;
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
