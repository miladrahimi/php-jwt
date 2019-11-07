<?php

namespace MiladRahimi\Jwt;

use MiladRahimi\Jwt\Base64\SafeBase64Parser;
use MiladRahimi\Jwt\Base64\Base64Parser;
use MiladRahimi\Jwt\Cryptography\Signer;
use MiladRahimi\Jwt\Json\StrictJsonParser;
use MiladRahimi\Jwt\Json\JsonParser;

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
     * @var JsonParser
     */
    private $jsonParser;

    /**
     * @var Base64Parser
     */
    private $base64Parser;

    /**
     * JwtGenerator constructor.
     *
     * @param Signer $signer
     * @param JsonParser|null $jsonParser
     * @param Base64Parser|null $base64Parser
     */
    public function __construct(
        Signer $signer,
        JsonParser $jsonParser = null,
        Base64Parser $base64Parser = null
    )
    {
        $this->setSigner($signer);
        $this->setJsonParser($jsonParser ?: new StrictJsonParser());
        $this->setBase64Parser($base64Parser ?: new SafeBase64Parser());
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
        $signature = $this->base64Parser->encode($this->signer->sign("$header.$payload"));

        return join('.', [$header, $payload, $signature]);
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
     * @return JsonParser
     */
    public function getJsonParser(): JsonParser
    {
        return $this->jsonParser;
    }

    /**
     * @param JsonParser $jsonParser
     */
    public function setJsonParser(JsonParser $jsonParser)
    {
        $this->jsonParser = $jsonParser;
    }

    /**
     * @return Base64Parser
     */
    public function getBase64Parser(): Base64Parser
    {
        return $this->base64Parser;
    }

    /**
     * @param Base64Parser $base64Parser
     */
    public function setBase64Parser(Base64Parser $base64Parser)
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
