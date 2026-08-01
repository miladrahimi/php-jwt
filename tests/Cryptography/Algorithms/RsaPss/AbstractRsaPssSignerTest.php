<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Tests\Cryptography\Algorithms\RsaPss;

use MiladRahimi\Jwt\Cryptography\Algorithms\RsaPss\PS256Signer;
use MiladRahimi\Jwt\Cryptography\Algorithms\RsaPss\PS256Verifier;
use MiladRahimi\Jwt\Cryptography\Keys\RsaPrivateKey;
use MiladRahimi\Jwt\Cryptography\Keys\RsaPublicKey;
use MiladRahimi\Jwt\Exceptions\SigningException;
use MiladRahimi\Jwt\Tests\TestCase;
use Throwable;

class AbstractRsaPssSignerTest extends TestCase
{
    /**
     * The signature the encoder must produce for the message `Text` under the 2041-bit fixture key with the
     * salt `fixedSaltSigner()` pins — that modulus leaves no excess bits to clear and prepends a zero byte, so
     * the whole encode path is pinned byte for byte and the encoded message keeps its `0xFF` leading byte. The
     * OpenSSL CLI verifies this vector (PSS with salt length 32).
     */
    private const FIXED_SALT_SIGNATURE_2041 =
        'ANo31z7z+wPHh8Afo/ZX+YErxy/Fj+ngyfgRVC8tVCyOEzdR9mec6bSG05nsE6oGubxSLyQ8V9MYQ0V7qSci+Wl6VT3digh8'
        . 'mJ3JkEtm+pQ7k6+VrBp9MYCC+yQmI6setHLV6DGqwIIMjyz3KrKwjxaAtYYDYvuTbBzNSSdSxSQsZinGUVLliT+E879Nh4rH'
        . '9JZLBX4egxByGyvTfoMKUAX3pNnQD/SqpEkJxdxJHiZtm1O2laOpk3oI4jp8Ke9OBJWOiV99JrjuSBiPuFzd1TzEpH2hEGHO'
        . 'hkT34v3iiawUYZ/vziuRMpk/11KjfqvmNN9aILyalsLgL+tVcGUdGg==';

    /**
     * The same vector under the 2047-bit fixture key, whose two excess bits the encoder must clear: the `0xFF`
     * leading byte of the encoded message has to come out as `0x3F`. Together with the 2041-bit vector, which
     * clears nothing, this pins the bit-clearing step for both shapes of modulus — no run of the suite depends
     * on a random salt happening to expose those bits. The OpenSSL CLI verifies this vector too.
     */
    private const FIXED_SALT_SIGNATURE_2047 =
        'A8kN0RON8TzrHc/0ZFhoyegSJoegm+oMmkOynOMJjY3HqFd7Nx2M4cAvAwfh1otJd6GPDKsKG5bC5GyB+FRig4TWqrliLR0P'
        . 'dyPMNNp5N0V+iXMsENOGtPEZ8ofnv6HK+Sn+PV2PuUr64K4suIrnSyvpcrZ1oUkCxHqOdbCYG7UwwnVg2AGNJoVoaE/qI5Y/'
        . 'oBynmdxLyFlqvlRM7th/p0iAO7qRDDJ3nedAWxgbjdpGJzXSpgy2SASk1KxUOwsTTy+BByVGPUJ39Ear/EqZ04t3ujLHboCZ'
        . '/iWYCiL2HfFDd/BCVW8amphnUMus3X4XpUVRGapGAyZGFs3NqCelkw==';

    protected RsaPrivateKey $rsaPrivateKey;

    protected RsaPublicKey $rsaPublicKey;

    public function setUp(): void
    {
        parent::setUp();

        $this->rsaPrivateKey = new RsaPrivateKey(__DIR__ . '/../../../../assets/keys/rsa-private.pem');
        $this->rsaPublicKey = new RsaPublicKey(__DIR__ . '/../../../../assets/keys/rsa-public.pem');
    }

    /**
     * EMSA-PSS is randomized: every signature embeds a fresh salt, so two signatures over the same message must
     * differ while both stay verifiable.
     *
     * @throws Throwable
     */
    public function test_sign_twice_it_should_produce_distinct_valid_signatures()
    {
        $signer = new PS256Signer($this->rsaPrivateKey);
        $verifier = new PS256Verifier($this->rsaPublicKey);

        $first = $signer->sign('Text');
        $second = $signer->sign('Text');

        $this->assertNotSame($first, $second);

        $verifier->verify('Text', $first);
        $verifier->verify('Text', $second);
    }

    /**
     * @throws Throwable
     */
    public function test_sign_it_should_produce_a_signature_of_the_modulus_size()
    {
        $signer = new PS256Signer($this->rsaPrivateKey);

        $this->assertSame(256, strlen($signer->sign('Text')));
    }

    /**
     * With the salt pinned, the whole EMSA-PSS encode path is deterministic and must reproduce the expected
     * signature byte for byte (see the constant above for how the vector was cross-checked).
     *
     * @throws Throwable
     */
    public function test_sign_with_a_fixed_salt_it_should_produce_the_expected_signature()
    {
        $signer = $this->fixedSaltSigner(KeyFixtures::PRIVATE_KEY_2041);

        $this->assertSame((string)base64_decode(self::FIXED_SALT_SIGNATURE_2041), $signer->sign('Text'));
    }

    /**
     * The same for a modulus that leaves excess bits to clear, so the signature also pins the bit-clearing step
     * of the encoding rather than only the bits a random salt happens to expose.
     *
     * @throws Throwable
     */
    public function test_sign_with_a_fixed_salt_and_excess_bits_it_should_produce_the_expected_signature()
    {
        $signer = $this->fixedSaltSigner(KeyFixtures::PRIVATE_KEY_2047);

        $this->assertSame((string)base64_decode(self::FIXED_SALT_SIGNATURE_2047), $signer->sign('Text'));
    }

    /**
     * A signer whose salt is pinned, which makes EMSA-PSS deterministic. The salt is chosen so the masked data
     * block starts with `0xFF` before the excess bits are cleared: every bit the encoder is supposed to clear
     * (or leave alone) is then visible in the signature, whatever the modulus size leaves over.
     *
     * @throws Throwable
     */
    private function fixedSaltSigner(string $privateKey): PS256Signer
    {
        return new class (new RsaPrivateKey($privateKey)) extends PS256Signer {
            protected function salt(int $length): string
            {
                return str_repeat("\xAB", $length - 1) . "\x72";
            }
        };
    }

    /**
     * The exception surfaces the pending OpenSSL error instead of the generic fallback message. Whether a failed
     * raw operation queues an error of its own varies by platform, so the queue is drained and re-seeded with a
     * known error to make its state deterministic.
     *
     * @throws Throwable
     */
    public function test_sign_with_a_wrong_modulus_size_it_should_carry_the_openssl_error()
    {
        $signer = new class ($this->rsaPrivateKey) extends PS256Signer {
            protected function modulusBits($key): int
            {
                return 2128; // 266-byte encoded message: too large for the raw RSA operation on a 2048-bit key
            }
        };

        while (openssl_error_string() !== false) {
            continue;
        }
        openssl_pkey_get_private('not-a-valid-key');

        try {
            $signer->sign('Text');
            $this->fail('A SigningException was expected.');
        } catch (SigningException $e) {
            $this->assertStringStartsWith('error:', $e->getMessage());
        }
    }
}
