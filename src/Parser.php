<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt;

use MiladRahimi\Jwt\Base64\Base64Parser;
use MiladRahimi\Jwt\Base64\SafeBase64Parser;
use MiladRahimi\Jwt\Cryptography\NamedVerifier;
use MiladRahimi\Jwt\Cryptography\Verifier;
use MiladRahimi\Jwt\Exceptions\InvalidSignatureException;
use MiladRahimi\Jwt\Exceptions\InvalidTokenException;
use MiladRahimi\Jwt\Exceptions\JsonDecodingException;
use MiladRahimi\Jwt\Exceptions\SigningException;
use MiladRahimi\Jwt\Exceptions\ValidationException;
use MiladRahimi\Jwt\Json\JsonParser;
use MiladRahimi\Jwt\Json\StrictJsonParser;
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

    /**
     * @var string[]
     */
    private array $validTypes;

    /**
     * @param string[] $validTypes The header `typ` values to accept, e.g. `['at+jwt']` for OAuth 2.0 access tokens
     *                             (RFC 9068); values are compared as media type names (see `validateType()`).
     */
    public function __construct(
        Verifier $verifier,
        ?Validator $validator = null,
        ?JsonParser $jsonParser = null,
        ?Base64Parser $base64Parser = null,
        array $validTypes = ['JWT']
    ) {
        $this->verifier = $verifier;
        $this->validator = $validator ?: new DefaultValidator();
        $this->jsonParser = $jsonParser ?: new StrictJsonParser();
        $this->base64Parser = $base64Parser ?: new SafeBase64Parser();
        $this->validTypes = $validTypes;
    }

    /**
     * Parses the JWT (verifies, decodes, and validates it) and returns the claims.
     *
     * @return array<int|string, mixed>
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
     * Splits the JWT into its three components.
     *
     * @return string[]
     * @throws Exceptions\InvalidTokenException
     */
    private function split(string $jwt): array
    {
        $sections = explode('.', $jwt);

        if (count($sections) !== 3) {
            throw new Exceptions\InvalidTokenException('The JWT format is not valid.');
        }

        return $sections;
    }

    /**
     * Verifies the JWT (validates the header and verifies the signature).
     *
     * @throws Exceptions\SigningException
     * @throws Exceptions\InvalidSignatureException
     * @throws Exceptions\InvalidTokenException
     * @throws Exceptions\JsonDecodingException
     */
    public function verify(string $jwt): void
    {
        [$header, $payload, $signature] = $this->split($jwt);

        $this->validateHeader($header);

        $this->verifySignature($header, $payload, $signature);
    }

    /**
     * Verifies the signature of the given JWT components.
     *
     * @throws Exceptions\SigningException
     * @throws Exceptions\InvalidSignatureException
     * @throws InvalidTokenException
     */
    private function verifySignature(string $header, string $payload, string $signature): void
    {
        $signature = $this->base64Parser->decode($signature);

        $this->verifier->verify("$header.$payload", $signature);
    }

    /**
     * Decodes the JWT payload and returns the claims.
     *
     * @return array<int|string, mixed>
     * @throws InvalidTokenException
     * @throws JsonDecodingException
     */
    private function decode(string $payload): array
    {
        return $this->jsonParser->decode($this->base64Parser->decode($payload));
    }

    /**
     * Validates the JWT (validates the header, verifies the signature, and validates the claims).
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

        $this->validateHeader($header);

        $this->verifySignature($header, $payload, $signature);

        $claims = $this->decode($payload);

        $this->validator->validate($claims);
    }

    /**
     * Validates the JWT header.
     *
     * @throws JsonDecodingException
     * @throws InvalidTokenException
     */
    public function validateHeader(string $header): void
    {
        $fields = $this->jsonParser->decode($this->base64Parser->decode($header));

        $this->validateType($fields);
        $this->validateAlgorithm($fields);
        $this->validateKeyId($fields);
    }

    /**
     * Validates the JWT type header field against the accepted types (`JWT` unless configured otherwise).
     *
     * @param array<int|string, mixed> $fields
     * @throws InvalidTokenException
     */
    private function validateType(array $fields): void
    {
        if (!isset($fields['typ'])) {
            throw new InvalidTokenException('The JWT header does not have a `typ` field.');
        }
        if (!is_string($fields['typ'])) {
            throw new InvalidTokenException('The JWT header `typ` field must be a string.');
        }

        foreach ($this->validTypes as $validType) {
            if ($this->normalizeType($fields['typ']) === $this->normalizeType($validType)) {
                return;
            }
        }

        throw new InvalidTokenException("The JWT type `{$fields['typ']}` is not supported.");
    }

    /**
     * Normalizes a `typ` value for comparison, following RFC 7515 Section 4.1.9: media type names are
     * case-insensitive, and a value without a slash is short for the same value prefixed with `application/`.
     */
    private function normalizeType(string $type): string
    {
        $type = strtolower($type);

        return strpos($type, '/') === false ? 'application/' . $type : $type;
    }

    /**
     * Validates the JWT algorithm header field when it is present.
     *
     * @param array<int|string, mixed> $fields
     * @throws InvalidTokenException
     */
    private function validateAlgorithm(array $fields): void
    {
        if (!isset($fields['alg'])) {
            return;
        }

        if (!is_string($fields['alg'])) {
            throw new InvalidTokenException('The JWT header `alg` field must be a string.');
        }

        $this->validateNamedAlgorithm($fields['alg']);
    }

    /**
     * Validates the algorithm declared for a named verifier.
     *
     * @throws InvalidTokenException
     */
    private function validateNamedAlgorithm(string $algorithm): void
    {
        // The verifier's algorithm is always the one used; this only rejects tokens whose `alg` contradicts it
        // (defense in depth). Custom verifiers opt in by implementing NamedVerifier.
        $verifier = $this->verifier;
        if ($verifier instanceof NamedVerifier && $algorithm !== $verifier->name()) {
            throw new InvalidTokenException("The token `alg` does not match the verifier's algorithm.");
        }
    }

    /**
     * Validates the JWT key ID header field when it is present.
     *
     * @param array<int|string, mixed> $fields
     * @throws InvalidTokenException
     */
    private function validateKeyId(array $fields): void
    {
        if (isset($fields['kid']) && $fields['kid'] !== $this->verifier->kid()) {
            throw new InvalidTokenException("The token `kid` does not match the verifier's key ID.");
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

    /**
     * @return string[]
     */
    public function getValidTypes(): array
    {
        return $this->validTypes;
    }
}
