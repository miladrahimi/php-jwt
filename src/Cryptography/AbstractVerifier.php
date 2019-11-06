<?php

namespace MiladRahimi\Jwt\Cryptography;

use MiladRahimi\Jwt\Base64\Base64Parser;
use MiladRahimi\Jwt\Base64\Base64;

/**
 * Class AbstractVerifier
 *
 * @package MiladRahimi\Jwt\Cryptography
 */
abstract class AbstractVerifier implements Verifier
{
    /**
     * @var Base64
     */
    protected $base64Parser;

    /**
     * AbstractAlgorithm constructor.
     *
     * @param Base64|null $base64Parser
     */
    public function __construct(Base64 $base64Parser = null)
    {
        if ($base64Parser) {
            $this->setBase64Parser($base64Parser);
        } else {
            $this->setBase64Parser(new Base64Parser());
        }
    }

    /**
     * @return Base64|null
     */
    public function getBase64Parser(): Base64
    {
        return $this->base64Parser;
    }

    /**
     * @param Base64 $base64Parser
     */
    public function setBase64Parser(Base64 $base64Parser)
    {
        $this->base64Parser = $base64Parser;
    }
}
