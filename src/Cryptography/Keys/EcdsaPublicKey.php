<?php declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography\Keys;

use MiladRahimi\Jwt\Exceptions\InvalidKeyException;
use Throwable;

class EcdsaPublicKey
{
    /**
     * @var resource    Key file resource handler
     */
    private $resource;

    /**
     * @throws InvalidKeyException
     */
    public function __construct(string $filePath)
    {
        try {
            $this->resource = openssl_pkey_get_public(file_get_contents(realpath($filePath)));

            if (empty($this->resource)) {
                throw new InvalidKeyException();
            }
        } catch (InvalidKeyException $e) {
            throw $e;
        } catch (Throwable $e) {
            throw new InvalidKeyException('Failed to read the key.', 0, $e);
        }
    }

    /**
     * @return resource
     */
    public function getResource()
    {
        return $this->resource;
    }

    /**
     * Close key resource
     */
    public function close()
    {
        unset($this->resource);
    }
}
