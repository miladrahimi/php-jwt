<?php declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography\Keys;

use MiladRahimi\Jwt\Exceptions\InvalidKeyException;
use Throwable;

class RsaPublicKey
{
    /**
     * @var mixed Key file resource handler
     */
    private $resource;

    protected ?string $id;

    /**
     * @throws InvalidKeyException
     */
    public function __construct(string $filePath, ?string $id = null)
    {
        try {
            $this->resource = openssl_pkey_get_public(file_get_contents(realpath($filePath)));
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
