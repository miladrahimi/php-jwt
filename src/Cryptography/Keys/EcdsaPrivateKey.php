<?php declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography\Keys;

use MiladRahimi\Jwt\Exceptions\InvalidKeyException;
use Throwable;

class EcdsaPrivateKey
{
    /**
     * @var mixed Key file resource handler
     */
    protected $resource;

    protected ?string $id;

    /**
     * @param string $key Key file path or string content
     * @param string $passphrase Key passphrase
     * @param string|null $id Key identifier
     *
     * @throws InvalidKeyException
     */
    public function __construct(string $key, string $passphrase = '', ?string $id = null)
    {
        $content = file_exists($key) ? file_get_contents($key) : $key;

        $this->resource = openssl_pkey_get_private($content, $passphrase);
        if ($this->resource === false) {
            throw new InvalidKeyException(openssl_error_string());
        }

        $this->id = $id;
    }

    /**
     * @return mixed
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
