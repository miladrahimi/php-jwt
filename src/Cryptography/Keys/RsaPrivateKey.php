<?php

namespace MiladRahimi\Jwt\Cryptography\Keys;

use MiladRahimi\Jwt\Exceptions\InvalidKeyException;
use Throwable;

/**
 * Class RsaPrivateKey
 *
 * @package MiladRahimi\Jwt\Cryptography\Keys
 */
class RsaPrivateKey
{
    /**
     * @var resource    Key file resource handler
     */
    private $resource;

    /**
     * PrivateKey constructor.
     *
     * @param string $filePath
     * @param string $passphrase
     * @throws InvalidKeyException
     */
    public function __construct(string $filePath, $passphrase = '')
    {
        try {
            $this->resource = openssl_pkey_get_private(file_get_contents(realpath($filePath)), $passphrase);

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
