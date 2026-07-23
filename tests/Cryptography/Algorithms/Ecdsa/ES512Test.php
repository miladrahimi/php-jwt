<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Tests\Cryptography\Algorithms\Ecdsa;

use MiladRahimi\Jwt\Cryptography\Algorithms\Ecdsa\ES512Signer;
use MiladRahimi\Jwt\Cryptography\Algorithms\Ecdsa\ES512Verifier;
use MiladRahimi\Jwt\Cryptography\Keys\EcdsaPrivateKey;
use MiladRahimi\Jwt\Cryptography\Keys\EcdsaPublicKey;
use MiladRahimi\Jwt\Exceptions\InvalidSignatureException;
use MiladRahimi\Jwt\Tests\TestCase;
use Throwable;

class ES512Test extends TestCase
{
    protected EcdsaPrivateKey $privateKey;
    protected EcdsaPublicKey $publicKey;

    public function setUp(): void
    {
        parent::setUp();

        $this->privateKey = new EcdsaPrivateKey(__DIR__ . '/../../../../assets/keys/ecdsa512-private.pem');
        $this->publicKey = new EcdsaPublicKey(__DIR__ . '/../../../../assets/keys/ecdsa512-public.pem');
    }

    /**
     * @throws Throwable
     */
    public function test_signer_and_verifier_they_should_sign_and_verify_with_the_pair_key()
    {
        $plain = 'Text';

        $signer = new ES512Signer($this->privateKey);
        $signature = $signer->sign($plain);

        $verifier = new ES512Verifier($this->publicKey);
        $verifier->verify($plain, $signature);

        $this->assertTrue(true);
    }

    /**
     * RFC 7518 §3.4 pairs ES512 with the P-521 curve, whose order is 521 bits — not a multiple of 8 — so each
     * signature coordinate occupies ceil(521 / 8) = 66 bytes and the raw JWS signature is exactly 132 bytes,
     * not the 128 that the algorithm name might suggest.
     *
     * @throws Throwable
     */
    public function test_sign_produces_a_132_byte_signature_of_two_66_byte_coordinates()
    {
        $signer = new ES512Signer($this->privateKey);

        $signature = $signer->sign('Header Payload');

        $this->assertSame(132, strlen($signature));
    }

    /**
     * RFC 7518 §3.1/§3.4 defines ES512 as "ECDSA using P-521 and SHA-512".
     * This is an interoperability proof: the signature our signer produces must be
     * verifiable by OpenSSL when — and only when — the SHA-512 digest is used.
     * A raw-OpenSSL verify with SHA-512 must pass, and one with SHA-384 must fail.
     * This locks the digest to SHA-512 and would catch a regression to any other digest.
     *
     * @throws Throwable
     */
    public function test_signature_uses_sha512_digest_per_rfc7518()
    {
        $plain = 'Header Payload';

        $signer = new ES512Signer($this->privateKey);
        // JWS carries the raw R||S signature; convert it back to DER for openssl_verify.
        $der = $this->signatureToDer($signer->sign($plain));

        $publicKeyResource = $this->publicKey->getResource();

        $this->assertSame(
            1,
            openssl_verify($plain, $der, $publicKeyResource, OPENSSL_ALGO_SHA512),
            'ES512 signature must verify with the SHA-512 digest (RFC 7518).'
        );

        $this->assertSame(
            0,
            openssl_verify($plain, $der, $publicKeyResource, OPENSSL_ALGO_SHA384),
            'ES512 signature must NOT verify with SHA-384.'
        );
    }

    /**
     * Cross-implementation e2e: verify a JWS-format ES512 signature produced entirely
     * outside this library — via raw OpenSSL with SHA-512 — is accepted by our Verifier.
     *
     * @throws Throwable
     */
    public function test_verifier_accepts_externally_signed_sha512_signature()
    {
        $plain = 'Header Payload';

        openssl_sign($plain, $der, $this->privateKey->getResource(), OPENSSL_ALGO_SHA512);
        $rawSignature = $this->derToJwsSignature($der);

        $verifier = new ES512Verifier($this->publicKey);
        $verifier->verify($plain, $rawSignature);

        $this->assertTrue(true);
    }

    /**
     * Convert a JWS raw R||S signature back to the DER SEQUENCE(INTEGER r, INTEGER s)
     * that openssl_verify expects. Mirrors AbstractEcdsaVerifier::signatureToDer,
     * including the long-form SEQUENCE length that P-521 signatures require.
     */
    private function signatureToDer(string $signature): string
    {
        $length = (int)(strlen($signature) / 2);
        $r = ltrim(substr($signature, 0, $length), "\x00");
        $s = ltrim(substr($signature, $length), "\x00");

        if (ord($r[0]) > 0x7f) {
            $r = "\x00" . $r;
        }
        if (ord($s[0]) > 0x7f) {
            $s = "\x00" . $s;
        }

        $seq = $this->derInteger($r) . $this->derInteger($s);

        return chr(0x30) . chr(0x81) . chr(strlen($seq)) . $seq;
    }

    private function derInteger(string $value): string
    {
        return chr(0x02) . chr(strlen($value)) . $value;
    }

    /**
     * Convert an OpenSSL DER ECDSA signature to the JWS raw R||S form (66-byte halves
     * for P-521). Independent of the library's own DER codec so it can attest to it.
     * P-521 signatures exceed 127 content bytes, so the SEQUENCE length is long form.
     */
    private function derToJwsSignature(string $der): string
    {
        $offset = 3; // skip SEQUENCE tag + long-form length (0x30 0x81 0xNN for P-521 signatures)

        $offset++; // INTEGER tag
        $rLen = ord($der[$offset++]);
        $r = ltrim(substr($der, $offset, $rLen), "\x00");
        $offset += $rLen;

        $offset++; // INTEGER tag
        $sLen = ord($der[$offset++]);
        $s = ltrim(substr($der, $offset, $sLen), "\x00");

        $r = str_pad($r, 66, "\x00", STR_PAD_LEFT);
        $s = str_pad($s, 66, "\x00", STR_PAD_LEFT);

        return $r . $s;
    }

    /**
     * ES512 signatures are 132 raw bytes; anything else is rejected before DER conversion.
     *
     * @throws Throwable
     */
    public function test_verify_with_truncated_signature_it_should_fail()
    {
        $signature = (new ES512Signer($this->privateKey))->sign('Text');

        $verifier = new ES512Verifier($this->publicKey);

        $this->expectException(InvalidSignatureException::class);
        $this->expectExceptionMessage('The signature length is not valid.');
        $verifier->verify('Text', substr($signature, 0, -1));
    }

    /**
     * A 128-byte signature (the "512 / 8 * 2" length ES512 might naively suggest) is rejected: P-521
     * coordinates are 66 bytes each, so only 132-byte signatures are structurally valid.
     *
     * @throws Throwable
     */
    public function test_verify_with_a_128_byte_signature_it_should_fail()
    {
        $verifier = new ES512Verifier($this->publicKey);

        $this->expectException(InvalidSignatureException::class);
        $this->expectExceptionMessage('The signature length is not valid.');
        $verifier->verify('Text', str_repeat("\x01", 128));
    }

    /**
     * @throws Throwable
     */
    public function test_signer_and_verifier_they_should_fail_with_different_plains()
    {
        $signer = new ES512Signer($this->privateKey);
        $signature = $signer->sign('Header Payload');

        $verifier = new ES512Verifier($this->publicKey);

        $this->expectException(InvalidSignatureException::class);
        $verifier->verify('Different!', $signature);
    }

    /**
     * @throws Throwable
     */
    public function test_set_and_get_private_key()
    {
        $key = $this->privateKey;

        $signer = new ES512Signer($key);

        $this->assertSame($key, $signer->getPrivateKey());
    }

    /**
     * @throws Throwable
     */
    public function test_set_and_get_public_key()
    {
        $key = $this->publicKey;

        $verifier = new ES512Verifier($key);

        $this->assertSame($key, $verifier->getPublicKey());
    }
}
