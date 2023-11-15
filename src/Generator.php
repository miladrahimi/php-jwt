<?php declare(strict_types=1);

namespace MiladRahimi\Jwt;

use MiladRahimi\Jwt\Base64\SafeBase64Parser;
use MiladRahimi\Jwt\Base64\Base64Parser;
use MiladRahimi\Jwt\Cryptography\Signer;
use MiladRahimi\Jwt\Json\StrictJsonParser;
use MiladRahimi\Jwt\Json\JsonParser;

/**
 * Generator creates JWTs from given claims
 */
class Generator
{
    private Signer $signer;

    private JsonParser $jsonParser;

    private Base64Parser $base64Parser;

    public function __construct(Signer $signer, JsonParser $jsonParser = null, Base64Parser $base64Parser = null)
    {
        $this->setSigner($signer);
        $this->setJsonParser($jsonParser ?: new StrictJsonParser());
        $this->setBase64Parser($base64Parser ?: new SafeBase64Parser());
    }

    /**
     * Generate JWT using given claims
     *
     * @throws Exceptions\JsonEncodingException
     * @throws Exceptions\SigningException
     */
    public function generate(array $claims = []): string
    {
        $header = $this->base64Parser->encode($this->jsonParser->encode($this->header()));
        $payload = $this->base64Parser->encode($this->jsonParser->encode($claims));
        $signature = $this->base64Parser->encode($this->signer->sign("$header.$payload"));

        return join('.', [$header, $payload, $signature]);
    }

    /**
     * Generate the JWT header
     */
    private function header(): array
    {
        return ['alg' => $this->signer->name(), 'typ' => 'JWT'];
    }

    public function getJsonParser(): JsonParser
    {
        return $this->jsonParser;
    }

    public function setJsonParser(JsonParser $jsonParser)
    {
        $this->jsonParser = $jsonParser;
    }

    public function getBase64Parser(): Base64Parser
    {
        return $this->base64Parser;
    }

    public function setBase64Parser(Base64Parser $base64Parser)
    {
        $this->base64Parser = $base64Parser;
    }

    public function getSigner(): Signer
    {
        return $this->signer;
    }

    public function setSigner(Signer $signer)
    {
        $this->signer = $signer;
    }
}
