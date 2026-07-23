<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt;

use InvalidArgumentException;
use MiladRahimi\Jwt\Base64\Base64Parser;
use MiladRahimi\Jwt\Base64\SafeBase64Parser;
use MiladRahimi\Jwt\Cryptography\Verifier;
use MiladRahimi\Jwt\Exceptions\InvalidTokenException;
use MiladRahimi\Jwt\Exceptions\JsonDecodingException;
use MiladRahimi\Jwt\Exceptions\NoKidException;
use MiladRahimi\Jwt\Exceptions\VerifierNotFoundException;
use MiladRahimi\Jwt\Json\JsonParser;
use MiladRahimi\Jwt\Json\StrictJsonParser;

/**
 * VerifierFactory maps a token's `kid` to the matching Verifier for
 * multi-key setups.
 */
class VerifierFactory
{
    private array $verifiers = [];

    private JsonParser $jsonParser;

    private Base64Parser $base64Parser;

    /**
     * @param Verifier[] $verifiers
     * @param JsonParser|null $jsonParser
     * @param Base64Parser|null $base64Parser
     */
    public function __construct(array $verifiers, ?JsonParser $jsonParser = null, ?Base64Parser $base64Parser = null)
    {
        foreach ($verifiers as $verifier) {
            if ($verifier instanceof Verifier) {
                $this->verifiers[$verifier->kid()] = $verifier;
            } else {
                throw new InvalidArgumentException(
                    'Values of the $verifiers array must be instances of MiladRahimi\Jwt\Cryptography\Verifier.'
                );
            }
        }

        $this->jsonParser = $jsonParser ?: new StrictJsonParser();
        $this->base64Parser = $base64Parser ?: new SafeBase64Parser();
    }

    /**
     * Returns the Verifier whose kid matches the given JWT's header.
     *
     * @throws InvalidTokenException
     * @throws JsonDecodingException
     * @throws NoKidException
     * @throws VerifierNotFoundException
     */
    public function getVerifier(string $jwt): Verifier
    {
        $header = $this->jsonParser->decode($this->base64Parser->decode($this->extractHeader($jwt)));

        if (isset($header['kid'])) {
            if (isset($this->verifiers[$header['kid']])) {
                return $this->verifiers[$header['kid']];
            }

            throw new VerifierNotFoundException("No verifier found for kid `{$header['kid']}`.");
        }

        throw new NoKidException();
    }

    /**
     * Extracts the header component of the given JWT.
     *
     * @throws Exceptions\InvalidTokenException
     */
    private function extractHeader(string $jwt): string
    {
        $sections = explode('.', $jwt);

        if (count($sections) !== 3) {
            throw new Exceptions\InvalidTokenException('The JWT format is not valid.');
        }

        return $sections[0];
    }
}
