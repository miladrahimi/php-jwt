<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Tests;

use MiladRahimi\Jwt\Base64\SafeBase64Parser;
use MiladRahimi\Jwt\Cryptography\Algorithms\Hmac\HS256;
use MiladRahimi\Jwt\Cryptography\Keys\HmacKey;
use MiladRahimi\Jwt\Cryptography\Verifier;
use MiladRahimi\Jwt\Enums\PublicClaimNames;
use MiladRahimi\Jwt\Exceptions\InvalidSignatureException;
use MiladRahimi\Jwt\Exceptions\InvalidTokenException;
use MiladRahimi\Jwt\Exceptions\ValidationException;
use MiladRahimi\Jwt\Generator;
use MiladRahimi\Jwt\Json\StrictJsonParser;
use MiladRahimi\Jwt\Parser;
use MiladRahimi\Jwt\Validator\BaseValidator;
use MiladRahimi\Jwt\Validator\Rules\EqualsTo;
use Throwable;

class ParserTest extends TestCase
{
    protected Verifier $verifier;

    public function setUp(): void
    {
        parent::setUp();

        $this->verifier = new HS256(new HmacKey('12345678901234567890123456789012'));
    }

    /**
     * @throws Throwable
     */
    public function test_parse_with_sample_jwt()
    {
        $parser = new Parser($this->verifier, new BaseValidator());
        $extractClaims = $parser->parse($this->sampleJwt);

        $this->assertEquals($this->sampleClaims, $extractClaims);
    }

    /**
     * @throws Throwable
     */
    public function test_validate_with_sample_jwt()
    {
        $parser = new Parser($this->verifier, new BaseValidator());
        $parser->validate($this->sampleJwt);

        $this->assertTrue(true);
    }

    /**
     * @throws Throwable
     */
    public function test_verify_with_sample_jwt()
    {
        $parser = new Parser($this->verifier);
        $parser->verify($this->sampleJwt);

        $this->assertTrue(true);
    }

    /**
     * @throws Throwable
     */
    public function test_parse_with_validator_it_should_pass_when_rules_are_ok()
    {
        $validator = new BaseValidator();
        $validator->addRequiredRule(PublicClaimNames::SUBJECT, new EqualsTo(666));

        $parser = new Parser($this->verifier, $validator);
        $extractClaims = $parser->parse($this->sampleJwt);

        $this->assertEquals($this->sampleClaims, $extractClaims);
    }

    /**
     * @throws Throwable
     */
    public function test_parse_with_validator_it_should_fail_when_rules_are_not_ok()
    {
        $validator = new BaseValidator();
        $validator->addRequiredRule('sub', new EqualsTo(13));

        $parser = new Parser($this->verifier, $validator);

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('The `sub` must be equal to `13`.');
        $parser->parse($this->sampleJwt);
    }

    /**
     * @throws Throwable
     */
    public function test_validate_with_validator_it_should_fail_when_rules_are_not_ok()
    {
        $validator = new BaseValidator();
        $validator->addRequiredRule('sub', new EqualsTo(13));

        $parser = new Parser($this->verifier, $validator);

        $this->expectException(ValidationException::class);
        $this->expectExceptionMessage('The `sub` must be equal to `13`.');
        $parser->validate($this->sampleJwt);
    }

    /**
     * @throws Throwable
     */
    public function test_parse_with_invalid_jwt_it_should_fail()
    {
        $invalidJwt = 'abc.xyz';

        $parser = new Parser($this->verifier);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('JWT format is not valid');
        $parser->parse($invalidJwt);
    }

    /**
     * @throws Throwable
     */
    public function test_parse_with_a_jwt_without_typ_it_should_fail()
    {
        $noTypJwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI2NjYifQ.cIDA-W5EVXB8Y3JQAgPRpIB19fDsaTHPgDg1XoTImA8';

        $parser = new Parser($this->verifier);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('The JWT header does not have a `typ` field.');
        $parser->parse($noTypJwt);
    }

    /**
     * @throws Throwable
     */
    public function test_parse_with_a_jwt_with_non_jwt_typ()
    {
        $noTypJwt = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IngifQ.eyJzdWIiOiI2NjYifQ' .
            '.Ut195bqywLi3TtWjo4461lVxo7RudOJGPdD1zBA_Z2gU';

        $parser = new Parser($this->verifier);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('The JWT type `x` is not supported.');
        $parser->parse($noTypJwt);
    }

    /**
     * A header whose `typ` field is not a string (e.g. an array) must be rejected cleanly instead of raising a PHP
     * type error.
     *
     * @throws Throwable
     */
    public function test_parse_with_a_jwt_with_non_string_typ_it_should_fail()
    {
        $base64Parser = new SafeBase64Parser();
        $header = $base64Parser->encode('{"typ":["JWT"],"alg":"HS256"}');
        $payload = $base64Parser->encode('{"sub":666}');

        $parser = new Parser($this->verifier);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('The JWT header `typ` field must be a string.');
        $parser->parse("$header.$payload.signature");
    }

    /**
     * Media type names are case-insensitive (RFC 7515 Section 4.1.9), so a lowercase `jwt` type must be accepted
     * by the default parser.
     *
     * @throws Throwable
     */
    public function test_parse_with_a_lowercase_typ_it_should_pass()
    {
        $jwt = $this->makeJwt('{"typ":"jwt","alg":"HS256"}', '{"sub":666}');

        $parser = new Parser($this->verifier, new BaseValidator());
        $claims = $parser->parse($jwt);

        $this->assertSame(666, $claims['sub']);
    }

    /**
     * RFC 7515 Section 4.1.9 requires recipients to treat a `typ` without a slash as if it were prefixed with
     * `application/`, so `application/jwt` must match the default `JWT` type.
     *
     * @throws Throwable
     */
    public function test_parse_with_a_prefixed_typ_it_should_pass()
    {
        $jwt = $this->makeJwt('{"typ":"application/jwt","alg":"HS256"}', '{"sub":666}');

        $parser = new Parser($this->verifier, new BaseValidator());
        $claims = $parser->parse($jwt);

        $this->assertSame(666, $claims['sub']);
    }

    /**
     * A parser configured for `at+jwt` accepts OAuth 2.0 access tokens (RFC 9068).
     *
     * @throws Throwable
     */
    public function test_parse_with_custom_valid_types_it_should_accept_matching_tokens()
    {
        $jwt = $this->makeJwt('{"typ":"at+jwt","alg":"HS256"}', '{"sub":666}');

        $parser = new Parser($this->verifier, new BaseValidator(), null, null, ['at+jwt']);
        $claims = $parser->parse($jwt);

        $this->assertSame(666, $claims['sub']);
    }

    /**
     * Explicit typing (RFC 8725 Section 3.11): a parser configured for `at+jwt` must reject plain `JWT` tokens.
     *
     * @throws Throwable
     */
    public function test_parse_with_custom_valid_types_it_should_reject_other_tokens()
    {
        $jwt = $this->makeJwt('{"typ":"JWT","alg":"HS256"}', '{"sub":666}');

        $parser = new Parser($this->verifier, new BaseValidator(), null, null, ['at+jwt']);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('The JWT type `JWT` is not supported.');
        $parser->parse($jwt);
    }

    /**
     * Normalization applies to the configured types too: a prefixed `application/at+jwt` configuration matches
     * the compact `at+jwt` form recommended by RFC 9068.
     *
     * @throws Throwable
     */
    public function test_parse_with_a_prefixed_valid_type_it_should_accept_the_compact_form()
    {
        $jwt = $this->makeJwt('{"typ":"at+jwt","alg":"HS256"}', '{"sub":666}');

        $parser = new Parser($this->verifier, new BaseValidator(), null, null, ['application/at+jwt']);
        $claims = $parser->parse($jwt);

        $this->assertSame(666, $claims['sub']);
    }

    /**
     * @throws Throwable
     */
    public function test_parse_with_multiple_valid_types_it_should_accept_any_of_them()
    {
        $parser = new Parser($this->verifier, new BaseValidator(), null, null, ['JWT', 'at+jwt']);

        $claims = $parser->parse($this->makeJwt('{"typ":"JWT","alg":"HS256"}', '{"sub":666}'));
        $this->assertSame(666, $claims['sub']);

        $claims = $parser->parse($this->makeJwt('{"typ":"at+jwt","alg":"HS256"}', '{"sub":13}'));
        $this->assertSame(13, $claims['sub']);
    }

    /**
     * A header whose `alg` contradicts the configured verifier's algorithm must be rejected (defense in depth
     * against alg confusion).
     *
     * @throws Throwable
     */
    public function test_parse_with_a_jwt_with_mismatched_alg_it_should_fail()
    {
        $base64Parser = new SafeBase64Parser();
        $header = $base64Parser->encode('{"typ":"JWT","alg":"RS256"}');
        $payload = $base64Parser->encode('{"sub":666}');

        $parser = new Parser($this->verifier);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage("The token `alg` does not match the verifier's algorithm.");
        $parser->parse("$header.$payload.signature");
    }

    /**
     * @throws Throwable
     */
    public function test_parse_with_a_jwt_with_non_string_alg_it_should_fail()
    {
        $base64Parser = new SafeBase64Parser();
        $header = $base64Parser->encode('{"typ":"JWT","alg":123}');
        $payload = $base64Parser->encode('{"sub":666}');

        $parser = new Parser($this->verifier);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('The JWT header `alg` field must be a string.');
        $parser->parse("$header.$payload.signature");
    }

    /**
     * The header `alg` check applies only to NamedVerifier implementations; a custom verifier without a name
     * accepts any declared algorithm (the verifier's own algorithm is still the only one used).
     *
     * @throws Throwable
     */
    public function test_parse_with_a_nameless_verifier_it_should_skip_the_alg_check()
    {
        $namelessVerifier = new class () implements Verifier {
            public function verify(string $plain, string $signature): void
            {
                // Accept everything; only header handling is under test here.
            }

            public function kid(): ?string
            {
                return null;
            }
        };

        $base64Parser = new SafeBase64Parser();
        $header = $base64Parser->encode('{"typ":"JWT","alg":"RS256"}');
        $payload = $base64Parser->encode('{"sub":666}');

        $parser = new Parser($namelessVerifier, new BaseValidator());
        $claims = $parser->parse("$header.$payload.sig0");

        $this->assertSame(666, $claims['sub']);
    }

    /**
     * All entry points (`parse`, `verify`, `validate`) run the same header validation.
     *
     * @throws Throwable
     */
    public function test_verify_with_a_jwt_without_typ_it_should_fail()
    {
        $noTypJwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI2NjYifQ.cIDA-W5EVXB8Y3JQAgPRpIB19fDsaTHPgDg1XoTImA8';

        $parser = new Parser($this->verifier);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('The JWT header does not have a `typ` field.');
        $parser->verify($noTypJwt);
    }

    /**
     * @throws Throwable
     */
    public function test_validate_with_a_jwt_without_typ_it_should_fail()
    {
        $noTypJwt = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiI2NjYifQ.cIDA-W5EVXB8Y3JQAgPRpIB19fDsaTHPgDg1XoTImA8';

        $parser = new Parser($this->verifier);

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage('The JWT header does not have a `typ` field.');
        $parser->validate($noTypJwt);
    }

    /**
     * A token whose signature has been replaced must be rejected.
     *
     * @throws Throwable
     */
    public function test_parse_fails_when_signature_is_tampered()
    {
        [$header, $payload] = explode('.', $this->sampleJwt);
        // 43 base64url chars = 32 zero bytes: a well-formed but wrong HS256 signature.
        $tamperedJwt = "$header.$payload." . str_repeat('A', 43);

        $parser = new Parser($this->verifier);

        $this->expectException(InvalidSignatureException::class);
        $parser->parse($tamperedJwt);
    }

    /**
     * A token whose payload has been altered must fail signature verification,
     * and must do so before the (tampered) claims are ever decoded/trusted.
     *
     * @throws Throwable
     */
    public function test_parse_fails_when_payload_is_tampered()
    {
        [$header, $payload, $signature] = explode('.', $this->sampleJwt);
        // Flip the final character of the payload; the original signature no longer matches.
        $tamperedPayload = substr($payload, 0, -1) . ($payload[-1] === 'A' ? 'B' : 'A');
        $tamperedJwt = "$header.$tamperedPayload.$signature";

        $parser = new Parser($this->verifier);

        $this->expectException(InvalidSignatureException::class);
        $parser->verify($tamperedJwt);
    }

    /**
     * When the header carries a `kid` that does not match the verifier's key id,
     * the token is rejected — before the signature is even checked.
     *
     * @throws Throwable
     */
    public function test_parse_fails_when_kid_does_not_match_verifier()
    {
        $keyContent = '12345678901234567890123456789012';
        $generator = new Generator(new HS256(new HmacKey($keyContent, 'key-1')));
        $jwt = $generator->generate(['sub' => 1]);

        // Same key material, different key id — only the kid differs.
        $parser = new Parser(new HS256(new HmacKey($keyContent, 'key-2')), new BaseValidator());

        $this->expectException(InvalidTokenException::class);
        $this->expectExceptionMessage("The token `kid` does not match the verifier's key ID.");
        $parser->parse($jwt);
    }

    /**
     * PHP's json_decode keeps the last occurrence of a duplicated claim; the signature covers the raw payload,
     * so this documents decoding behavior for consumers comparing with other JWT implementations.
     *
     * @throws Throwable
     */
    public function test_parse_with_duplicate_claims_it_should_keep_the_last_value()
    {
        $base64Parser = new SafeBase64Parser();
        $header = $base64Parser->encode('{"typ":"JWT","alg":"HS256"}');
        $payload = $base64Parser->encode('{"sub":1,"sub":2}');
        $signature = $base64Parser->encode($this->verifier->sign("$header.$payload"));

        $parser = new Parser($this->verifier, new BaseValidator());
        $claims = $parser->parse("$header.$payload.$signature");

        $this->assertSame(2, $claims['sub']);
    }

    /**
     * The header `kid` check applies only when the token carries one: a keyed verifier accepts kid-less tokens.
     *
     * @throws Throwable
     */
    public function test_parse_passes_when_token_has_no_kid_but_verifier_does()
    {
        $keyedHmac = new HS256(new HmacKey('12345678901234567890123456789012', 'key-1'));

        $base64Parser = new SafeBase64Parser();
        $header = $base64Parser->encode('{"typ":"JWT","alg":"HS256"}');
        $payload = $base64Parser->encode('{"sub":1}');
        $signature = $base64Parser->encode($keyedHmac->sign("$header.$payload"));

        $parser = new Parser($keyedHmac, new BaseValidator());
        $claims = $parser->parse("$header.$payload.$signature");

        $this->assertSame(1, $claims['sub']);
    }

    /**
     * A token whose header `kid` matches the verifier's key id parses successfully.
     *
     * @throws Throwable
     */
    public function test_parse_passes_when_kid_matches_verifier()
    {
        $keyContent = '12345678901234567890123456789012';
        $generator = new Generator(new HS256(new HmacKey($keyContent, 'key-1')));
        $jwt = $generator->generate(['sub' => 1]);

        $parser = new Parser(new HS256(new HmacKey($keyContent, 'key-1')), new BaseValidator());
        $claims = $parser->parse($jwt);

        $this->assertSame(1, $claims['sub']);
    }

    public function test_set_and_get_verifier()
    {
        $parser = new Parser($this->verifier);

        $this->assertSame($this->verifier, $parser->getVerifier());
    }

    public function test_set_and_get_validator()
    {
        $validator = new BaseValidator();
        $parser = new Parser($this->verifier, $validator);

        $this->assertSame($validator, $parser->getValidator());
    }

    public function test_set_and_get_json_parser()
    {
        $jsonParser = new StrictJsonParser();
        $parser = new Parser($this->verifier, null, $jsonParser);

        $this->assertSame($jsonParser, $parser->getJsonParser());
    }

    public function test_set_and_get_base64_parser()
    {
        $base64Parser = new SafeBase64Parser();
        $parser = new Parser($this->verifier, null, null, $base64Parser);

        $this->assertSame($base64Parser, $parser->getBase64Parser());
    }

    public function test_set_and_get_valid_types()
    {
        $parser = new Parser($this->verifier, null, null, null, ['at+jwt']);

        $this->assertSame(['at+jwt'], $parser->getValidTypes());
    }

    public function test_get_valid_types_defaults_to_jwt()
    {
        $parser = new Parser($this->verifier);

        $this->assertSame(['JWT'], $parser->getValidTypes());
    }

    /**
     * `validate()` must reject a token whose signature has been replaced, just like `parse()` and `verify()`.
     *
     * @throws Throwable
     */
    public function test_validate_fails_when_signature_is_tampered()
    {
        [$header, $payload] = explode('.', $this->sampleJwt);
        // 43 base64url chars = 32 zero bytes: a well-formed but wrong HS256 signature.
        $tamperedJwt = "$header.$payload." . str_repeat('A', 43);

        $parser = new Parser($this->verifier, new BaseValidator());

        $this->expectException(InvalidSignatureException::class);
        $parser->validate($tamperedJwt);
    }

    /**
     * The `alg` header field is optional, so a valid header without it must pass validation.
     *
     * @throws Throwable
     */
    public function test_validate_header_without_alg_it_should_pass()
    {
        $header = (new SafeBase64Parser())->encode('{"typ":"JWT"}');

        $parser = new Parser($this->verifier);
        $parser->validateHeader($header);

        $this->assertTrue(true);
    }

    /**
     * `validateHeader` is part of the public API and is callable on its own.
     *
     * @throws Throwable
     */
    public function test_validate_header_with_a_valid_header_it_should_pass()
    {
        $header = (new SafeBase64Parser())->encode('{"typ":"JWT","alg":"HS256"}');

        $parser = new Parser($this->verifier);
        $parser->validateHeader($header);

        $this->assertTrue(true);
    }

    /**
     * Builds an HS256-signed JWT from raw header and payload JSON, bypassing the Generator.
     */
    private function makeJwt(string $headerJson, string $payloadJson): string
    {
        $base64Parser = new SafeBase64Parser();
        $header = $base64Parser->encode($headerJson);
        $payload = $base64Parser->encode($payloadJson);
        $signature = $base64Parser->encode($this->verifier->sign("$header.$payload"));

        return "$header.$payload.$signature";
    }
}
