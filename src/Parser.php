<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt;

use MiladRahimi\Jwt\Base64\SafeBase64Parser;
use MiladRahimi\Jwt\Base64\Base64Parser;
use MiladRahimi\Jwt\Cryptography\Verifier;
use MiladRahimi\Jwt\Exceptions\InvalidSignatureException;
use MiladRahimi\Jwt\Exceptions\InvalidTokenException;
use MiladRahimi\Jwt\Exceptions\JsonDecodingException;
use MiladRahimi\Jwt\Exceptions\SigningException;
use MiladRahimi\Jwt\Exceptions\ValidationException;
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
    ) {
        $this->verifier = $verifier;
        $this->validator = $validator ?: new DefaultValidator();
        $this->jsonParser = $jsonParser ?: new StrictJsonParser();
        $this->base64Parser = $base64Parser ?: new SafeBase64Parser();
    }

    /**
     * Parse (verify, decode, and validate) the JWT and extract claims
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

        $this->validateHeader($header);

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
            throw new Exceptions\InvalidTokenException('JWT format is not valid.');
        }

        return $sections;
    }

    /**
     * Verify the JWT (verify the signature)
     *
     * @throws Exceptions\SigningException
     * @throws Exceptions\InvalidSignatureException
     * @throws Exceptions\InvalidTokenException
     */
    public function verify(string $jwt): void
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
    private function verifySignature(string $header, string $payload, string $signature): void
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
     * @throws ValidationException
     * @throws InvalidSignatureException
     * @throws InvalidTokenException
     * @throws JsonDecodingException
     * @throws SigningException
     */
    public function validate(string $jwt): void
    {
        [$header, $payload, $signature] = $this->split($jwt);

        $this->verifySignature($header, $payload, $signature);

        $claims = $this->decode($payload);

        $this->validator->validate($claims);
    }

    /**
     * @throws JsonDecodingException
     * @throws InvalidTokenException
     */
    public function validateHeader(string $header): void
    {
        $fields = $this->jsonParser->decode($this->base64Parser->decode($header));

        if (!isset($fields['typ'])) {
            throw new InvalidTokenException('JWT header does not have `typ` field.');
        }
        if ($fields['typ'] !== 'JWT') {
            throw new InvalidTokenException("JWT of type `{$fields['typ']}` is not supported.");
        }

        if (isset($fields['kid'])) {
            if ($fields['kid'] !== $this->verifier->kid()) {
                throw new InvalidTokenException("The kid is not compatible with key ID.");
            }
        }
    }

    public function getJsonParser(): JsonParser
    {
        return $this->jsonParser;
    }

    public function getBase64Parser(): Base64Parser
    {
        return $this->base64Parser;
    }

    public function getVerifier(): Verifier
    {
        return $this->verifier;
    }

    public function getValidator(): Validator
    {
        return $this->validator;
    }
}
