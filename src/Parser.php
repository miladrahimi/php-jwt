<?php declare(strict_types=1);

namespace MiladRahimi\Jwt;

use MiladRahimi\Jwt\Base64\SafeBase64Parser;
use MiladRahimi\Jwt\Base64\Base64Parser;
use MiladRahimi\Jwt\Cryptography\Verifier;
use MiladRahimi\Jwt\Json\StrictJsonParser;
use MiladRahimi\Jwt\Json\JsonParser;
use MiladRahimi\Jwt\Validator\DefaultValidator;
use MiladRahimi\Jwt\Validator\Validator;

/**
 * The parser is responsible for verifying, decoding, and validating
 * JSON Web Tokens (JWTs), extracting the contained claims.
 */
class Parser
{
    private Verifier $verifier;

    private Validator $validator;

    private JsonParser $jsonParser;

    private Base64Parser $base64Parser;

    public function __construct(
        Verifier      $verifier,
        ?Validator    $validator = null,
        ?JsonParser   $jsonParser = null,
        ?Base64Parser $base64Parser = null
    )
    {
        $this->setVerifier($verifier);
        $this->setValidator($validator ?: new DefaultValidator());
        $this->setJsonParser($jsonParser ?: new StrictJsonParser());
        $this->setBase64Parser($base64Parser ?: new SafeBase64Parser());
    }

    /**
     * Parse (verify, decode, and validate) the JWT, then extract claims
     *
     * @throws Exceptions\SigningException
     * @throws Exceptions\InvalidSignatureException
     * @throws Exceptions\InvalidTokenException
     * @throws Exceptions\JsonDecodingException
     * @throws Exceptions\ValidationException
     */
    public function parse(string $jwt): array
    {
        [$header, $payload, $signature] = $this->split($jwt);

        $this->verifySignature($header, $payload, $signature);

        $claims = $this->decode($payload);

        $this->validator->validate($claims);

        return $claims;
    }

    /**
     * Split (explode) JWT to its components
     *
     * @throws Exceptions\InvalidTokenException
     */
    private function split(string $jwt): array
    {
        $sections = explode('.', $jwt);

        if (count($sections) !== 3) {
            throw new Exceptions\InvalidTokenException('JWT format is not valid');
        }

        return $sections;
    }

    /**
     * Verify the JWT (check the signature)
     *
     * @throws Exceptions\SigningException
     * @throws Exceptions\InvalidSignatureException
     * @throws Exceptions\InvalidTokenException
     */
    public function verify(string $jwt)
    {
        [$header, $payload, $signature] = $this->split($jwt);

        $this->verifySignature($header, $payload, $signature);
    }

    /**
     * Verify the JWT signature
     *
     * @throws Exceptions\SigningException
     * @throws Exceptions\InvalidSignatureException
     */
    private function verifySignature(string $header, string $payload, string $signature)
    {
        $signature = $this->base64Parser->decode($signature);

        $this->verifier->verify("$header.$payload", $signature);
    }

    /**
     * Decode JWT and extract claims
     *
     * @throws Exceptions\JsonDecodingException
     */
    private function decode(string $payload): array
    {
        return $this->jsonParser->decode($this->base64Parser->decode($payload));
    }

    /**
     * Validate JWT (verify signature and validate claims)
     *
     * @throws Exceptions\SigningException
     * @throws Exceptions\InvalidSignatureException
     * @throws Exceptions\InvalidTokenException
     * @throws Exceptions\JsonDecodingException
     * @throws Exceptions\ValidationException
     */
    public function validate(string $jwt)
    {
        list($header, $payload, $signature) = $this->split($jwt);

        $this->verifySignature($header, $payload, $signature);

        $claims = $this->decode($payload);

        $this->validator->validate($claims);
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
     * @return Verifier
     */
    public function getVerifier(): Verifier
    {
        return $this->verifier;
    }

    /**
     * @param Verifier $verifier
     */
    public function setVerifier(Verifier $verifier)
    {
        $this->verifier = $verifier;
    }

    /**
     * @return Validator
     */
    public function getValidator(): Validator
    {
        return $this->validator;
    }

    /**
     * @param Validator $validator
     */
    public function setValidator(Validator $validator)
    {
        $this->validator = $validator;
    }
}
