<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography\Keys;

use MiladRahimi\Jwt\Exceptions\InvalidKeyException;

class Ed448PublicKey
{
    /**
     * @var resource|\OpenSSLAsymmetricKey The OpenSSL key handle.
     * @phpstan-var resource
     */
    protected $resource;

    protected ?string $id;

    /**
     * @param string $key Key file path or string content
     * @param string|null $id Key identifier
     *
     * @throws InvalidKeyException
     */
    public function __construct(string $key, ?string $id = null)
    {
        // The constant exists exactly when openssl_sign()/openssl_verify() accept Ed448 keys (PHP 8.4+ built
        // against an OpenSSL with Ed448), so it gates the whole algorithm at key construction.
        if (!defined('OPENSSL_KEYTYPE_ED448')) {
            throw new InvalidKeyException('Ed448 keys require PHP 8.4 or later with OpenSSL Ed448 support.');
        }

        $content = is_file($key) ? (string)file_get_contents($key) : $key;

        $resource = openssl_pkey_get_public($content);
        if ($resource === false) {
            throw new InvalidKeyException(openssl_error_string() ?: 'The key is not valid.');
        }

        $this->resource = $resource;

        $this->id = $id;
    }

    /**
     * @return resource|\OpenSSLAsymmetricKey The OpenSSL key handle.
     * @phpstan-return resource
     */
    public function getResource()
    {
        return $this->resource;
    }

    public function getId(): ?string
    {
        return $this->id;
    }
}
