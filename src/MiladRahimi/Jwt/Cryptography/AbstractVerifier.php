<?php
/**
 * Created by PhpStorm.
 * User: Milad Rahimi <info@miladrahimi.com>
 * Date: 5/15/2018 AD
 * Time: 23:25
 */

namespace MiladRahimi\Jwt\Cryptography;

use MiladRahimi\Jwt\Base64\Base64Parser;
use MiladRahimi\Jwt\Base64\Base64ParserInterface;

abstract class AbstractVerifier implements Verifier
{
    /**
     * @var Base64ParserInterface
     */
    protected $base64Parser;

    /**
     * AbstractAlgorithm constructor.
     *
     * @param Base64ParserInterface|null $base64Parser
     */
    public function __construct(Base64ParserInterface $base64Parser = null)
    {
        if ($base64Parser) {
            $this->setBase64Parser($base64Parser);
        } else {
            $this->setBase64Parser(new Base64Parser());
        }
    }

    /**
     * @return Base64ParserInterface|null
     */
    public function getBase64Parser(): Base64ParserInterface
    {
        return $this->base64Parser;
    }

    /**
     * @param Base64ParserInterface $base64Parser
     */
    public function setBase64Parser(Base64ParserInterface $base64Parser)
    {
        $this->base64Parser = $base64Parser;
    }
}