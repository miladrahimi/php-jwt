<?php

namespace MiladRahimi\Jwt\Cryptography\Keys;

use MiladRahimi\Jwt\Exceptions\InvalidKeyException;

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
        $this->resource = openssl_pkey_get_private('file:///' . $filePath, $passphrase);

        if (empty($this->resource)) {
            throw new InvalidKeyException();
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
        openssl_free_key($this->getResource());
    }
}
