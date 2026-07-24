<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Tests\Cryptography\Algorithms\Ecdsa;

use MiladRahimi\Jwt\Cryptography\Algorithms\Ecdsa\ES256Verifier;
use MiladRahimi\Jwt\Cryptography\Keys\EcdsaPublicKey;
use MiladRahimi\Jwt\Exceptions\InvalidSignatureException;
use MiladRahimi\Jwt\Tests\TestCase;
use Throwable;

class AbstractEcdsaVerifierTest extends TestCase
{
    protected EcdsaPublicKey $publicKey;

    public function setUp(): void
    {
        parent::setUp();

        $this->publicKey = new EcdsaPublicKey(__DIR__ . '/../../../../assets/keys/ecdsa256-public.pem');
    }

    /**
     * Builds a verifier whose protected raw-to-DER converter is publicly reachable.
     */
    private function verifier(): ES256Verifier
    {
        return new class ($this->publicKey) extends ES256Verifier {
            public function signatureToDerPublicly(string $signature): string
            {
                return $this->signatureToDer($signature);
            }
        };
    }

    /**
     * A raw `R || S` signature becomes a DER SEQUENCE of the two INTEGERs.
     *
     * @throws Throwable
     */
    public function test_signature_to_der_with_single_byte_integers()
    {
        $der = $this->verifier()->signatureToDerPublicly("\x01\x02");

        $this->assertSame("\x30\x06\x02\x01\x01\x02\x01\x02", $der);
    }

    /**
     * Leading zero bytes are stripped from both halves before DER encoding.
     *
     * @throws Throwable
     */
    public function test_signature_to_der_strips_the_zero_padding_of_both_integers()
    {
        $der = $this->verifier()->signatureToDerPublicly("\x00\x01\x00\x02");

        $this->assertSame("\x30\x06\x02\x01\x01\x02\x01\x02", $der);
    }

    /**
     * A top byte of exactly 0x7f keeps the integer positive, so no sign byte is prepended.
     *
     * @throws Throwable
     */
    public function test_signature_to_der_does_not_pad_integers_with_a_top_byte_of_7f()
    {
        $der = $this->verifier()->signatureToDerPublicly("\x7f\x7f");

        $this->assertSame("\x30\x06\x02\x01\x7f\x02\x01\x7f", $der);
    }

    /**
     * A top byte above 0x7f gets a 0x00 sign byte, in both halves, so the INTEGERs are not misread as negative.
     *
     * @throws Throwable
     */
    public function test_signature_to_der_pads_integers_with_a_high_top_byte()
    {
        $der = $this->verifier()->signatureToDerPublicly("\x80\x81");

        $this->assertSame("\x30\x08\x02\x02\x00\x80\x02\x02\x00\x81", $der);
    }

    /**
     * A zero integer still occupies one 0x00 byte in DER, in both halves.
     *
     * @throws Throwable
     */
    public function test_signature_to_der_keeps_one_byte_for_zero_integers()
    {
        $der = $this->verifier()->signatureToDerPublicly("\x00\x00");

        $this->assertSame("\x30\x06\x02\x01\x00\x02\x01\x00", $der);
    }

    /**
     * A SEQUENCE of exactly 127 content bytes — the largest value the short form can express — keeps the
     * single-byte length. Together with the 128-byte case below, this pins the exact long-form boundary.
     *
     * @throws Throwable
     */
    public function test_signature_to_der_with_127_content_bytes_it_should_keep_the_short_form_length()
    {
        // Halves must be equal-sized; the leading zero of the first one is stripped, giving 61- and 62-byte
        // INTEGERs: (2 + 61) + (2 + 62) = 127 content bytes.
        $signature = "\x00" . str_repeat("\x01", 61) . str_repeat("\x01", 62);

        $der = $this->verifier()->signatureToDerPublicly($signature);

        $this->assertSame(
            "\x30\x7f" . "\x02\x3d" . str_repeat("\x01", 61) . "\x02\x3e" . str_repeat("\x01", 62),
            $der
        );
    }

    /**
     * A SEQUENCE of 128 content bytes no longer fits the short form: its length gets the one-byte long form
     * (`0x81` prefix), as every P-521 (ES512) signature does.
     *
     * @throws Throwable
     */
    public function test_signature_to_der_with_128_content_bytes_it_should_use_the_long_form_length()
    {
        // Two 62-byte INTEGERs: (2 + 62) * 2 = 128 content bytes.
        $signature = str_repeat("\x01", 62) . str_repeat("\x01", 62);

        $der = $this->verifier()->signatureToDerPublicly($signature);

        $this->assertSame(
            "\x30\x81\x80" . "\x02\x3e" . str_repeat("\x01", 62) . "\x02\x3e" . str_repeat("\x01", 62),
            $der
        );
    }

    /**
     * The exception surfaces the pending OpenSSL error instead of the generic fallback message. Whether a failed
     * verification queues an error of its own varies by platform, so the queue is drained and re-seeded with a
     * known error to make its state deterministic.
     *
     * @throws Throwable
     */
    public function test_verify_with_a_wrong_signature_it_should_carry_the_openssl_error()
    {
        while (openssl_error_string() !== false) {
            continue;
        }
        openssl_pkey_get_private('not-a-valid-key');

        $verifier = new ES256Verifier($this->publicKey);

        try {
            $verifier->verify('Plain', str_repeat("\x01", 64));
            $this->fail('An InvalidSignatureException was expected.');
        } catch (InvalidSignatureException $e) {
            $this->assertStringStartsWith('error:', $e->getMessage());
        }
    }
}
