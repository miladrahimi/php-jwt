<?php

namespace MiladRahimi\Jwt;

use MiladRahimi\Jwt\Base64\Base64Parser;
use MiladRahimi\Jwt\Base64\Base64ParserInterface;
use MiladRahimi\Jwt\Cryptography\Signer;
use MiladRahimi\Jwt\Json\JsonParser;
use MiladRahimi\Jwt\Json\JsonParserInterface;

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
     * @var JsonParserInterface
     */
    private $jsonParser;

    /**
     * @var Base64ParserInterface
     */
    private $base64Parser;

    /**
     * JwtGenerator constructor.
     *
     * @param Signer $signer
     * @param JsonParserInterface|null $jsonParser
     * @param Base64ParserInterface|null $base64Parser
     */
    public function __construct(
        Signer $signer,
        JsonParserInterface $jsonParser = null,
        Base64ParserInterface $base64Parser = null
    ) {
        $this->setSigner($signer);
        $this->setJsonParser($jsonParser ?: new JsonParser());
        $this->setBase64Parser($base64Parser ?: new Base64Parser());
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
     * @return JsonParserInterface
     */
    public function getJsonParser(): JsonParserInterface
    {
        return $this->jsonParser;
    }

    /**
     * @param JsonParserInterface $jsonParser
     */
    public function setJsonParser(JsonParserInterface $jsonParser)
    {
        $this->jsonParser = $jsonParser;
    }

    /**
     * @return Base64ParserInterface
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
