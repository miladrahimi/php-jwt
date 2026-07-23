<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography\Keys;

use MiladRahimi\Jwt\Exceptions\InvalidKeyException;

class RsaPublicKey
{
    /**
     * @var resource The OpenSSL key handle (an OpenSSLAsymmetricKey object on PHP 8+).
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
        $content = is_file($key) ? (string)file_get_contents($key) : $key;

        $resource = openssl_pkey_get_public($content);
        if ($resource === false) {
            throw new InvalidKeyException(openssl_error_string() ?: 'The key is not valid.');
        }

        $this->resource = $resource;

        $this->id = $id;
    }

    /**
     * @return resource The OpenSSL key handle (an OpenSSLAsymmetricKey object on PHP 8+).
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
