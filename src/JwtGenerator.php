<?php

namespace MiladRahimi\Jwt;

use MiladRahimi\Jwt\Base64\SafeBase64;
use MiladRahimi\Jwt\Base64\Base64;
use MiladRahimi\Jwt\Cryptography\Signer;
use MiladRahimi\Jwt\Json\JsonParser;
use MiladRahimi\Jwt\Json\Json;

/**
 * Class JwtGenerator
 *
 * @package MiladRahimi\Jwt
 */
class JwtGenerator
{
    /**
     * @var Signer
     */
    private $signer;

    /**
     * @var Json
     */
    private $jsonParser;

    /**
     * @var Base64
     */
    private $base64Parser;

    /**
     * JwtGenerator constructor.
     *
     * @param Signer $signer
     * @param Json|null $jsonParser
     * @param Base64|null $base64Parser
     */
    public function __construct(
        Signer $signer,
        Json $jsonParser = null,
        Base64 $base64Parser = null
    ) {
        $this->setSigner($signer);
        $this->setJsonParser($jsonParser ?: new JsonParser());
        $this->setBase64Parser($base64Parser ?: new SafeBase64());
    }

    /**
     * Generate JWT from given claims
     *
     * @param array $claims
     * @return string JWT
     * @throws Exceptions\JsonEncodingException
     */
    public function generate(array $claims = []): string
    {
        $header = $this->base64Parser->encode($this->jsonParser->encode($this->generateHeader()));

        $payload = $this->base64Parser->encode($this->jsonParser->encode($claims));

        $signature = $this->base64Parser->encode($this->signer->sign($header . '.' . $payload));

        return $header . '.' . $payload . '.' . $signature;
    }

    /**
     * Generate JWT header
     *
     * @return string[] [alg, type]
     */
    private function generateHeader(): array
    {
        return ['alg' => $this->signer->getName(), 'typ' => 'JWT'];
    }

    /**
     * @return Json
     */
    public function getJsonParser(): Json
    {
        return $this->jsonParser;
    }

    /**
     * @param Json $jsonParser
     */
    public function setJsonParser(Json $jsonParser)
    {
        $this->jsonParser = $jsonParser;
    }

    /**
     * @return Base64
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

    /**
     * @return Signer
     */
    public function getSigner(): Signer
    {
        return $this->signer;
    }

    /**
     * @param Signer $signer
     */
    public function setSigner(Signer $signer)
    {
        $this->signer = $signer;
    }
}
