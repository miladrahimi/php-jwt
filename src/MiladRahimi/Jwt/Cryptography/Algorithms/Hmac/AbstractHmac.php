<?php
/**
 * Created by PhpStorm.
 * User: Milad Rahimi <info@miladrahimi.com>
 * Date: 5/14/2018 AD
 * Time: 00:18
 */

namespace MiladRahimi\Jwt\Cryptography\Algorithms\Hmac;

use MiladRahimi\Jwt\Base64\Base64ParserInterface;
use MiladRahimi\Jwt\Cryptography\AbstractVerifier;
use MiladRahimi\Jwt\Cryptography\Signer;
use MiladRahimi\Jwt\Exceptions\InvalidKeyException;
use MiladRahimi\Jwt\Exceptions\InvalidSignatureException;

abstract class AbstractHmac extends AbstractVerifier implements Signer
{
    /**
     * @var string
     */
    protected $name;

    /**
     * @var string
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
    public function verify(string $header, string $payload, string $signature): void
    {
        $tokenSignature = $this->base64Parser->encode($this->sign($header . '.' . $payload));

        if ($tokenSignature != $signature) {
            throw new InvalidSignatureException();
        }
    }

    /**
     * @inheritdoc
     */
    public function sign(string $data): string
    {
        return hash_hmac($this->algorithmName(), $data, $this->key, true);
    }

    /**
     * Convert JWT algorithm name to hash function name
     *
     * @return string
     */
    protected function algorithmName(): string
    {
        return 'sha' . substr($this->name, 2);
    }

    /**
     * @return string
     */
    public function getName(): string
    {
        return $this->name;
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
    public function setKey(string $key): void
    {
        if (strlen($key) < 32 || strlen($key) > 6144) {
            throw new InvalidKeyException();
        }

        $this->key = $key;
    }
}