<?php

namespace MiladRahimi\Jwt\Cryptography\Keys;

use MiladRahimi\Jwt\Exceptions\InvalidKeyException;

/**
 * Class PublicKey
 *
 * @package MiladRahimi\Jwt\Cryptography\Keys
 */
class PublicKey
{
    /**
     * @var resource    Key file resource handler
     */
    private $resource;

    /**
     * PublicKey constructor.
     *
     * @param string $fileFullPath
     * @throws InvalidKeyException
     */
    public function __construct(string $fileFullPath)
    {
        $this->resource = openssl_pkey_get_public('file:///' . $fileFullPath);

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
}
