<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Tests\Cryptography\Algorithms\Ecdsa;

use MiladRahimi\Jwt\Cryptography\Algorithms\Ecdsa\ES384Signer;
use MiladRahimi\Jwt\Cryptography\Algorithms\Ecdsa\ES384Verifier;
use MiladRahimi\Jwt\Cryptography\Keys\EcdsaPrivateKey;
use MiladRahimi\Jwt\Cryptography\Keys\EcdsaPublicKey;
use MiladRahimi\Jwt\Exceptions\InvalidSignatureException;
use MiladRahimi\Jwt\Tests\TestCase;
use Throwable;

class ES384Test extends TestCase
{
    protected EcdsaPrivateKey $privateKey;
    protected EcdsaPublicKey $publicKey;

    public function setUp(): void
    {
        parent::setUp();

        $this->privateKey = new EcdsaPrivateKey(__DIR__ . '/../../../../assets/keys/ecdsa384-private.pem');
        $this->publicKey = new EcdsaPublicKey(__DIR__ . '/../../../../assets/keys/ecdsa384-public.pem');
    }

    /**
     * @throws Throwable
     */
    public function test_signer_and_verifier_they_should_sign_and_verify_with_the_pair_key()
    {
        $plain = 'Text';

        $signer = new ES384Signer($this->privateKey);
        $signature = $signer->sign($plain);

        $verifier = new ES384Verifier($this->publicKey);
        $verifier->verify($plain, $signature);

        $this->assertTrue(true);
    }

    /**
     * RFC 7518 §3.1/§3.4 defines ES384 as "ECDSA using P-384 and SHA-384".
     * This is an interoperability proof: the signature our signer produces must be
     * verifiable by OpenSSL when — and only when — the SHA-384 digest is used.
     * A raw-OpenSSL verify with SHA-384 must pass, and one with SHA-512 (the old,
     * non-compliant behaviour) must fail. This locks the digest to SHA-384 and would
     * catch any regression back to SHA-512.
     *
     * @throws Throwable
     */
    public function test_signature_uses_sha384_digest_per_rfc7518()
    {
        $plain = 'Header Payload';

        $signer = new ES384Signer($this->privateKey);
        // JWS carries the raw R||S signature; convert it back to DER for openssl_verify.
        $der = $this->signatureToDer($signer->sign($plain));

        $publicKeyResource = $this->publicKey->getResource();

        $this->assertSame(
            1,
            openssl_verify($plain, $der, $publicKeyResource, OPENSSL_ALGO_SHA384),
            'ES384 signature must verify with the SHA-384 digest (RFC 7518).'
        );

        $this->assertSame(
            0,
            openssl_verify($plain, $der, $publicKeyResource, OPENSSL_ALGO_SHA512),
            'ES384 signature must NOT verify with SHA-512 (the old, non-compliant digest).'
        );
    }

    /**
     * Cross-implementation e2e: verify a JWS-format ES384 signature produced entirely
     * outside this library — via raw OpenSSL with SHA-384 — is accepted by our Verifier.
     * If ES384 were still hashing with SHA-512, our Verifier would reject this token.
     *
     * @throws Throwable
     */
    public function test_verifier_accepts_externally_signed_sha384_signature()
    {
        $plain = 'Header Payload';

        openssl_sign($plain, $der, $this->privateKey->getResource(), OPENSSL_ALGO_SHA384);
        $rawSignature = $this->derToJwsSignature($der);

        $verifier = new ES384Verifier($this->publicKey);
        $verifier->verify($plain, $rawSignature);

        $this->assertTrue(true);
    }

    /**
     * Convert a JWS raw R||S signature back to the DER SEQUENCE(INTEGER r, INTEGER s)
     * that openssl_verify expects. Mirrors AbstractEcdsaVerifier::signatureToDer.
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

        return chr(0x30) . chr(strlen($seq)) . $seq;
    }

    private function derInteger(string $value): string
    {
        return chr(0x02) . chr(strlen($value)) . $value;
    }

    /**
     * Convert an OpenSSL DER ECDSA signature to the JWS raw R||S form (48-byte halves
     * for P-384). Independent of the library's own DER codec so it can attest to it.
     */
    private function derToJwsSignature(string $der): string
    {
        $offset = 2; // skip SEQUENCE tag + length (short form for P-384 signatures)

        $offset++; // INTEGER tag
        $rLen = ord($der[$offset++]);
        $r = ltrim(substr($der, $offset, $rLen), "\x00");
        $offset += $rLen;

        $offset++; // INTEGER tag
        $sLen = ord($der[$offset++]);
        $s = ltrim(substr($der, $offset, $sLen), "\x00");

        $r = str_pad($r, 48, "\x00", STR_PAD_LEFT);
        $s = str_pad($s, 48, "\x00", STR_PAD_LEFT);

        return $r . $s;
    }

    /**
     * ES384 signatures are 96 raw bytes; anything else is rejected before DER conversion.
     *
     * @throws Throwable
     */
    public function test_verify_with_truncated_signature_it_should_fail()
    {
        $signature = (new ES384Signer($this->privateKey))->sign('Text');

        $verifier = new ES384Verifier($this->publicKey);

        $this->expectException(InvalidSignatureException::class);
        $this->expectExceptionMessage('The signature length is not valid.');
        $verifier->verify('Text', substr($signature, 0, -1));
    }

    /**
     * @throws Throwable
     */
    public function test_signer_and_verifier_they_should_fail_with_different_plains()
    {
        $signer = new ES384Signer($this->privateKey);
        $signature = $signer->sign('Header Payload');

        $verifier = new ES384Verifier($this->publicKey);

        $this->expectException(InvalidSignatureException::class);
        $verifier->verify('Different!', $signature);
    }

    /**
     * @throws Throwable
     */
    public function test_set_and_get_private_key()
    {
        $key = $this->privateKey;

        $signer = new ES384Signer($key);

        $this->assertSame($key, $signer->getPrivateKey());
    }

    /**
     * @throws Throwable
     */
    public function test_set_and_get_public_key()
    {
        $key = $this->publicKey;

        $verifier = new ES384Verifier($key);

        $this->assertSame($key, $verifier->getPublicKey());
    }
}
