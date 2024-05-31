<?php declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography\Keys;

use MiladRahimi\Jwt\Exceptions\InvalidKeyException;
use Throwable;

class EcdsaPublicKey
{
    /**
     * @var mixed Key file resource handler
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
        try {
            $content = file_exists($key) ? file_get_contents($key) : $key;
            $this->resource = openssl_pkey_get_public($content);
        } catch (Throwable $e) {
            throw new InvalidKeyException('Failed to read the key.', 0, $e);
        }

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
