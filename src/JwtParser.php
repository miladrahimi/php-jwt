<?php

namespace MiladRahimi\Jwt;

use MiladRahimi\Jwt\Base64\Base64Parser;
use MiladRahimi\Jwt\Base64\Base64ParserInterface;
use MiladRahimi\Jwt\Cryptography\Verifier;
use MiladRahimi\Jwt\Exceptions\JsonDecodingException;
use MiladRahimi\Jwt\Exceptions\InvalidSignatureException;
use MiladRahimi\Jwt\Exceptions\InvalidTokenException;
use MiladRahimi\Jwt\Exceptions\ValidationException;
use MiladRahimi\Jwt\Json\JsonParser;
use MiladRahimi\Jwt\Json\JsonParserInterface;
use MiladRahimi\Jwt\Validator\DefaultValidator;
use MiladRahimi\Jwt\Validator\Validator;
use MiladRahimi\Jwt\Validator\ValidatorInterface;

/**
 * Class JwtParser
 *
 * @package MiladRahimi\Jwt
 */
class JwtParser
{
    /**
     * @var Verifier
     */
    private $verifier;

    /**
     * @var JsonParserInterface
     */
    private $jsonParser;

    /**
     * @var Base64ParserInterface
     */
    private $base64Parser;

    /**
     * @var ValidatorInterface
     */
    private $validator;

    /**
     * JwtParser constructor.
     *
     * @param Verifier $verifier
     * @param Validator|null $validator
     * @param JsonParserInterface|null $jsonParser
     * @param Base64ParserInterface|null $base64Parser
     */
    public function __construct(
        Verifier $verifier,
        Validator $validator = null,
        JsonParserInterface $jsonParser = null,
        Base64ParserInterface $base64Parser = null
    ) {
        $this->setVerifier($verifier);
        $this->setValidator($validator ?: new DefaultValidator());
        $this->setJsonParser($jsonParser ?: new JsonParser());
        $this->setBase64Parser($base64Parser ?: new Base64Parser());
    }

    /**
     * Parse (verify and validate) JWT and retrieve claims
     *
     * @param string $jwt
     * @return array[]
     * @throws JsonDecodingException
     * @throws InvalidSignatureException
     * @throws InvalidTokenException
     * @throws ValidationException
     */
    public function parse(string $jwt): array
    {
        $this->verifySignature($jwt);

        $claims = $this->extractClaims($jwt);
        $this->validateClaims($claims);

        return $claims;
    }

    /**
     * Verify JWT signature
     *
     * @param string $jwt
     * @return void
     * @throws InvalidSignatureException
     * @throws InvalidTokenException
     */
    public function verifySignature(string $jwt)
    {
        list($header, $payload, $signature) = $this->explodeJwt($jwt);

        $this->verifier->verify($header, $payload, $signature);
    }

    /**
     * Explode jwt to its sections
     *
     * @param string $jwt
     * @return string[] [header, payload, signature]
     * @throws InvalidTokenException
     */
    private function explodeJwt(string $jwt): array
    {
        $sections = explode('.', $jwt);

        if (count($sections) != 3) {
            throw new InvalidTokenException('Token format is not valid');
        }

        return [$sections[0], $sections[1], $sections[2]];
    }

    /**
     * Extract claims from JWT
     *
     * @param string $jwt
     * @return array
     * @throws JsonDecodingException
     */
    private function extractClaims(string $jwt): array
    {
        $payload = $this->explodeJwt($jwt)[1];

        return $this->jsonParser->decode($this->base64Parser->decode($payload));
    }

    /**
     * Validate claims
     *
     * @param array $claims
     * @throws ValidationException
     */
    public function validateClaims(array $claims)
    {
        $this->validator->validate($claims);
    }

    /**
     * Validate JWT (verify signature and validate claims)
     *
     * @param string $jwt
     * @throws JsonDecodingException
     * @throws InvalidSignatureException
     * @throws InvalidTokenException
     * @throws ValidationException
     */
    public function validate(string $jwt)
    {
        $this->verifySignature($jwt);

        $claims = $this->extractClaims($jwt);
        $this->validateClaims($claims);
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
     * @return ValidatorInterface
     */
    public function getValidator(): ValidatorInterface
    {
        return $this->validator;
    }

    /**
     * @param ValidatorInterface $validator
     */
    public function setValidator(ValidatorInterface $validator)
    {
        $this->validator = $validator;
    }
}
