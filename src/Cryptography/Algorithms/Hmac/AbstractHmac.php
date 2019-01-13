<?php

namespace MiladRahimi\Jwt\Cryptography\Algorithms\Hmac;

use MiladRahimi\Jwt\Base64\Base64ParserInterface;
use MiladRahimi\Jwt\Cryptography\AbstractVerifier;
use MiladRahimi\Jwt\Cryptography\Signer;
use MiladRahimi\Jwt\Exceptions\InvalidKeyException;
use MiladRahimi\Jwt\Exceptions\InvalidSignatureException;
use MiladRahimi\Jwt\Exceptions\SigningException;

/**
 * Class AbstractHmac
 *
 * @package MiladRahimi\Jwt\Cryptography\Algorithms\Hmac
 */
abstract class AbstractHmac extends AbstractVerifier implements Signer
{
    /**
     * @var string  Algorithm name
     */
    protected static $name;

    /**
     * @var string  Encryption key
     */
    protected $key;

    /**
     * HS constructor.
     *
     * @param string $key
     * @param Base64ParserInterface|null $base64Parser
     * @throws InvalidKeyException
     */
    public function __construct(string $key, Base64ParserInterface $base64Parser = null)
    {
        parent::__construct($base64Parser);

        $this->setKey($key);
    }

    /**
     * @inheritdoc
     */
    public function verify(string $header, string $payload, string $signature)
    {
        $tokenSignature = $this->base64Parser->encode($this->sign($header . '.' . $payload));

        if ($tokenSignature != $signature) {
            throw new InvalidSignatureException();
        }
    }

    /**
     * @inheritdoc
     */
    public function sign(string $plain): string
    {
        $signature = hash_hmac($this->algorithmName(), $plain, $this->key, true);

        if ($signature === false) {
            throw new SigningException();
        }

        return $signature;
    }

    /**
     * Convert JWT algorithm name to hash function name
     *
     * @return string
     */
    protected function algorithmName(): string
    {
        return 'sha' . substr($this->getName(), 2);
    }

    /**
     * @return string
     */
    public function getName(): string
    {
        return static::$name;
    }

    /**
     * @return string
     */
    public function getKey(): string
    {
        return $this->key;
    }

    /**
     * @param string $key
     * @throws InvalidKeyException
     */
    public function setKey(string $key)
    {
        if (strlen($key) < 32 || strlen($key) > 6144) {
            throw new InvalidKeyException();
        }

        $this->key = $key;
    }
}
