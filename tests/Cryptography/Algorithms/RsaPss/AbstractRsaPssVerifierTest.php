<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Tests\Cryptography\Algorithms\RsaPss;

use MiladRahimi\Jwt\Cryptography\Algorithms\RsaPss\PS256Signer;
use MiladRahimi\Jwt\Cryptography\Algorithms\RsaPss\PS256Verifier;
use MiladRahimi\Jwt\Cryptography\Algorithms\RsaPss\PS512Verifier;
use MiladRahimi\Jwt\Cryptography\Keys\RsaPrivateKey;
use MiladRahimi\Jwt\Cryptography\Keys\RsaPublicKey;
use MiladRahimi\Jwt\Exceptions\InvalidSignatureException;
use MiladRahimi\Jwt\Tests\TestCase;
use Throwable;

/**
 * Exercises the EMSA-PSS consistency check directly with crafted encoded messages, and the full verify() path
 * with the fixed odd-size keys from KeyFixtures, whose paths byte-aligned keys never reach. The signature
 * vectors were generated with the OpenSSL CLI over the message `Text`:
 * `openssl dgst -sha256 -sign <key> -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:-1`.
 */
class AbstractRsaPssVerifierTest extends TestCase
{
    private const SIGNATURE_2047 =
        'Mzf+cMznbGashWhIJ78e3HcMUMpCZeulSFR2zrY5geM6INn3a40gMeK0S+VcGIj341erzQjEsLtlN8K5aG/GyS0HfBt/WxVo'
        . 'bs141KghLZvaO0/g4vzH07IIdJDP9uYHC80xQb7/k+5KyHKwkhYdJgROWiT897rn20ztBJl3Ff/EuJpcNWJe+rPdFCrMScGt'
        . 'cbvlQKqMCHng/Nh2h1vuqlwAJ3vvSZxzVPpqA/efe3HNEJ63OjM2VE0shEdtBZiX9w95kDB9UjUEWAX2ErbgRpRQu8E9ARec'
        . 'm6tSQIm5v/F8Z8akCUVbSSGX73483SL0c3aHgurkrCNtkwutAr+5Bg==';

    private const SIGNATURE_2041 =
        'AI5HrDe+F7lkYoU4j2YKwx2v/hsFLcl4wHRVCN2vHTaTcLu+G3oyplEO7vAEpihstljZqUmZWUcee9321IISlV029goNWu/f'
        . 'R2+QoRsDCdhwJO1ktIOYo+YguLbCH3H1iZ4mYUIjzWhfP8XP0q+8lhuSigPDWWP5w7GoyJjQCyZT40KGsCJGMSUmFyhAqbXE'
        . 'X7Ne4xzsvWV9g7Kaj/Q26+ugWOfGumlOhUJjzlOvnYlmsCPDs0zkuRT+CvM8hf335bF6/knz3V1EGNp5d45TXF16qFK7jB+2'
        . 'F01WpgC5S5b/cMjCcUmETWi3rnvjffiRB00r1knlTetNxwQVAKjAzw==';

    private const SIGNATURE_2042 =
        'AboGjs6cEG4geypYeOVvv2EhXyR53PF6t+FdfVmx7Mc0+DCr1GkLfOQ8v58UOrtLbB6BjPVdsdTzMhMSqMG4q9KphTtgay0m'
        . 'J/G0yTL6V0qGaaEHWpxNBI+dRSixLRrIx/7AcqdVNmy5Q2UgnQNZG3bmombFVbiscPgZgJie4NwS2+2CSLfdeJTcbLBqAGOk'
        . 'YMmMToAVJCg+5dyx3yoaYzGbghe725B/gwGgKN5twmXQi0oSD6UpmzAvMioCiNk5+pENFpFydT5KxIuHkzjzl53qgcsNlGr9'
        . 'JX+gOwm4/Uzvm54BekTppkZ7Xr/l7tobp0qmqgQFprjCy/RJt5Rdbw==';

    /**
     * The raw RSA private-key operation over `\x01` followed by a fully valid 255-byte EMSA-PSS encoding of
     * `Text` (fixed salt `\xAB` * 32) under the 2041-bit key: everything after the leading byte is consistent,
     * so only the leading-byte check can reject it.
     */
    private const SIGNATURE_2041_NONZERO_LEADING_BYTE =
        'AFHHxPB5qMnJIjgmfVev2Pp504HAzfHYWIRRpu5QUx6yGHEUh4P0gC8AUeM09li7xpiXSGkOBaYTym6+NTT4HcyTFdIMuW8+'
        . 'V8DuGWcIAQXozuinytVZOttAx+GqqmmuwXfZNz96Aer4lpQ86mWc8y4VGbYXCDouY74ZS6DngA8wjNmebp50L4KXo44p5Lyv'
        . 'i6oqtQQrabv6T3F/xi8w13quNHDgGARq1BYzUfh88qghjh/h6Tm3XT1bUsPf3i4E1nra6+oQs0TnMz0ErBaHW5chczFXnazp'
        . 'vSDuw641Vs/miMT1gTW8HjZ0zggn9h1bIxohFXkMoqNxhYD2UEmrEw==';

    protected RsaPrivateKey $rsaPrivateKey;

    protected RsaPublicKey $rsaPublicKey;

    public function setUp(): void
    {
        parent::setUp();

        $this->rsaPrivateKey = new RsaPrivateKey(__DIR__ . '/../../../../assets/keys/rsa-private.pem');
        $this->rsaPublicKey = new RsaPublicKey(__DIR__ . '/../../../../assets/keys/rsa-public.pem');
    }

    /**
     * Builds a verifier whose protected EMSA-PSS internals are publicly reachable.
     *
     * @return PS256Verifier
     */
    private function verifier(?RsaPublicKey $key = null)
    {
        return new class ($key ?? $this->rsaPublicKey) extends PS256Verifier {
            public function isConsistentPublicly(string $message, string $encoded, int $emBits): bool
            {
                return $this->isConsistent($message, $encoded, $emBits);
            }

            public function mgf1Publicly(string $seed, int $length): string
            {
                return $this->mgf1($seed, $length);
            }
        };
    }

    /**
     * Builds an EMSA-PSS encoded message with SHA-256, a fixed salt, and overridable padding and separator
     * bytes, so each structural check can be violated one at a time. The default emBits = 2047 matches a
     * 2048-bit key (emLen = 256); emBits = 2040 gives a 255-byte encoding with no excess bits to clear.
     */
    private function encodedMessage(
        string $message,
        string $padding = "\x00",
        string $separator = "\x01",
        int $emBits = 2047
    ): string {
        $emLength = intdiv($emBits + 7, 8);
        $salt = str_repeat("\xAB", 32);
        $hash = hash('sha256', str_repeat("\x00", 8) . hash('sha256', $message, true) . $salt, true);

        $db = str_repeat($padding, $emLength - 32 - 32 - 2) . $separator . $salt;
        $maskedDb = $db ^ $this->verifier()->mgf1Publicly($hash, $emLength - 32 - 1);
        $maskedDb[0] = chr(ord($maskedDb[0]) & (0xFF >> (8 * $emLength - $emBits)));

        return $maskedDb . $hash . "\xBC";
    }

    /**
     * @throws Throwable
     */
    public function test_is_consistent_with_a_well_formed_encoding_it_should_pass()
    {
        $encoded = $this->encodedMessage('Text');

        $this->assertTrue($this->verifier()->isConsistentPublicly('Text', $encoded, 2047));
    }

    /**
     * @throws Throwable
     */
    public function test_is_consistent_with_a_wrong_trailer_byte_it_should_fail()
    {
        $encoded = substr($this->encodedMessage('Text'), 0, -1) . "\xBB";

        $this->assertFalse($this->verifier()->isConsistentPublicly('Text', $encoded, 2047));
    }

    /**
     * @throws Throwable
     */
    public function test_is_consistent_with_a_nonzero_padding_byte_it_should_fail()
    {
        $encoded = $this->encodedMessage('Text', "\x02");

        $this->assertFalse($this->verifier()->isConsistentPublicly('Text', $encoded, 2047));
    }

    /**
     * At emBits = 2040 no bits are cleared from the first data-block byte, so flipping only its lowest bit
     * (through the mask) must be caught by the zero-padding comparison itself, with no help from bit clearing.
     *
     * @throws Throwable
     */
    public function test_is_consistent_with_a_low_bit_flipped_in_the_first_padding_byte_it_should_fail()
    {
        $encoded = $this->encodedMessage('Text', "\x00", "\x01", 2040);
        $encoded[0] = chr(ord($encoded[0]) ^ 0x01);

        $this->assertFalse($this->verifier()->isConsistentPublicly('Text', $encoded, 2040));
    }

    /**
     * @throws Throwable
     */
    public function test_is_consistent_with_a_wrong_separator_byte_it_should_fail()
    {
        $encoded = $this->encodedMessage('Text', "\x00", "\x02");

        $this->assertFalse($this->verifier()->isConsistentPublicly('Text', $encoded, 2047));
    }

    /**
     * @throws Throwable
     */
    public function test_is_consistent_with_a_set_excess_bit_it_should_fail()
    {
        $encoded = $this->encodedMessage('Text');
        $encoded[0] = chr(ord($encoded[0]) | 0x80);

        $this->assertFalse($this->verifier()->isConsistentPublicly('Text', $encoded, 2047));
    }

    /**
     * @throws Throwable
     */
    public function test_is_consistent_with_a_corrupted_hash_it_should_fail()
    {
        $encoded = $this->encodedMessage('Text');
        $encoded[240] = chr(ord($encoded[240]) ^ 0x01); // offset 240 is inside H (bytes 223 through 254)

        $this->assertFalse($this->verifier()->isConsistentPublicly('Text', $encoded, 2047));
    }

    /**
     * @throws Throwable
     */
    public function test_is_consistent_with_a_wrong_encoding_length_it_should_fail()
    {
        $encoded = $this->encodedMessage('Text') . "\x00";

        $this->assertFalse($this->verifier()->isConsistentPublicly('Text', $encoded, 2047));
    }

    /**
     * A valid encoding with an extra trailer byte appended still ends in `\xBC` and carries a consistent
     * prefix, so only the length comparison can reject it.
     *
     * @throws Throwable
     */
    public function test_is_consistent_with_an_extra_trailer_byte_it_should_fail()
    {
        $encoded = $this->encodedMessage('Text') . "\xBC";

        $this->assertFalse($this->verifier()->isConsistentPublicly('Text', $encoded, 2047));
    }

    /**
     * emLen = 65 at emBits = 519 is below the hLen + sLen + 2 = 66 minimum for SHA-256 (RFC 8017 §9.1.2).
     *
     * @throws Throwable
     */
    public function test_is_consistent_with_an_encoding_below_the_minimum_length_it_should_fail()
    {
        $this->assertFalse($this->verifier()->isConsistentPublicly('Text', str_repeat("\x00", 65), 519));
    }

    /**
     * @throws Throwable
     */
    public function test_mgf1_it_should_produce_exactly_the_requested_length()
    {
        $this->assertSame(223, strlen($this->verifier()->mgf1Publicly('seed', 223)));
        $this->assertSame(32, strlen($this->verifier()->mgf1Publicly('seed', 32)));
    }

    /**
     * A 2047-bit modulus leaves two excess bits (8 * 256 - 2046) to clear and check instead of the usual one.
     *
     * @throws Throwable
     */
    public function test_verify_with_a_2047_bit_key_openssl_cli_signature_it_should_pass()
    {
        $verifier = new PS256Verifier(new RsaPublicKey(KeyFixtures::PUBLIC_KEY_2047));
        $verifier->verify('Text', (string)base64_decode(self::SIGNATURE_2047));

        $this->assertTrue(true);
    }

    /**
     * @throws Throwable
     */
    public function test_sign_and_verify_with_a_2047_bit_key_it_should_pass()
    {
        $signer = new PS256Signer(new RsaPrivateKey(KeyFixtures::PRIVATE_KEY_2047));
        $signature = $signer->sign('Text');

        $verifier = new PS256Verifier(new RsaPublicKey(KeyFixtures::PUBLIC_KEY_2047));
        $verifier->verify('Text', $signature);

        $this->assertTrue(true);
    }

    /**
     * A 2041-bit modulus makes the encoded message one byte shorter than the 256-byte modulus, so the recovered
     * message carries a leading zero byte that the verifier must strip (and require).
     *
     * @throws Throwable
     */
    public function test_verify_with_a_2041_bit_key_openssl_cli_signature_it_should_pass()
    {
        $verifier = new PS256Verifier(new RsaPublicKey(KeyFixtures::PUBLIC_KEY_2041));
        $verifier->verify('Text', (string)base64_decode(self::SIGNATURE_2041));

        $this->assertTrue(true);
    }

    /**
     * @throws Throwable
     */
    public function test_sign_and_verify_with_a_2041_bit_key_it_should_pass()
    {
        $signer = new PS256Signer(new RsaPrivateKey(KeyFixtures::PRIVATE_KEY_2041));
        $signature = $signer->sign('Text');

        $verifier = new PS256Verifier(new RsaPublicKey(KeyFixtures::PUBLIC_KEY_2041));
        $verifier->verify('Text', $signature);

        $this->assertTrue(true);
    }

    /**
     * A 2042-bit modulus shifts the encoded-message length arithmetic by a single bit (emBits = 2041 still
     * rounds up to 256 bytes); the vector fails to verify if that arithmetic is off by even one.
     *
     * @throws Throwable
     */
    public function test_verify_with_a_2042_bit_key_openssl_cli_signature_it_should_pass()
    {
        $verifier = new PS256Verifier(new RsaPublicKey(KeyFixtures::PUBLIC_KEY_2042));
        $verifier->verify('Text', (string)base64_decode(self::SIGNATURE_2042));

        $this->assertTrue(true);
    }

    /**
     * @throws Throwable
     */
    public function test_verify_with_a_nonzero_leading_byte_it_should_fail()
    {
        $verifier = new PS256Verifier(new RsaPublicKey(KeyFixtures::PUBLIC_KEY_2041));

        $this->expectException(InvalidSignatureException::class);
        $this->expectExceptionMessage('The signature is not valid.');
        $verifier->verify('Text', (string)base64_decode(self::SIGNATURE_2041_NONZERO_LEADING_BYTE));
    }

    /**
     * A 129-byte signature that decrypts to zeros ending in the `\xBC` trailer: too small for PS512 (emLen =
     * 129 < 130), yet shaped so that only the RFC 8017 minimum-length guard stands between it and the
     * deeper checks, which would fail on out-of-range lengths instead of returning cleanly.
     *
     * @throws Throwable
     */
    public function test_verify_with_a_trailer_only_signature_and_a_too_small_key_it_should_fail()
    {
        $resource = openssl_pkey_new(['private_key_bits' => 1032, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
        $publicPem = openssl_pkey_get_details($resource)['key'];

        $encoded = str_repeat("\x00", 128) . "\xBC";
        $signature = null;
        openssl_private_encrypt($encoded, $signature, $resource, OPENSSL_NO_PADDING);

        $verifier = new PS512Verifier(new RsaPublicKey($publicPem));

        $this->expectException(InvalidSignatureException::class);
        $this->expectExceptionMessage('The signature is not valid.');
        $verifier->verify('Text', (string)$signature);
    }

    /**
     * The exception surfaces the pending OpenSSL error instead of the generic fallback message. An all-0xFF
     * signature exceeds the modulus, so the raw RSA operation itself fails. Whether a failed operation queues
     * an error of its own varies by platform, so the queue is drained and re-seeded with a known error to make
     * its state deterministic.
     *
     * @throws Throwable
     */
    public function test_verify_with_a_signature_above_the_modulus_it_should_carry_the_openssl_error()
    {
        while (openssl_error_string() !== false) {
            continue;
        }
        openssl_pkey_get_private('not-a-valid-key');

        $verifier = new PS256Verifier($this->rsaPublicKey);

        try {
            $verifier->verify('Text', str_repeat("\xFF", 256));
            $this->fail('An InvalidSignatureException was expected.');
        } catch (InvalidSignatureException $e) {
            $this->assertStringStartsWith('error:', $e->getMessage());
        }
    }
}
