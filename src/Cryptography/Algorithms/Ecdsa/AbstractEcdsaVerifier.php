<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography\Algorithms\Ecdsa;

use MiladRahimi\Jwt\Cryptography\Keys\EcdsaPublicKey;
use MiladRahimi\Jwt\Cryptography\Verifier;
use MiladRahimi\Jwt\Exceptions\InvalidSignatureException;

use function chr;
use function ltrim;
use function ord;
use function str_split;
use function strlen;

abstract class AbstractEcdsaVerifier implements Verifier
{
    use Algorithm;

    protected const ASN1_INTEGER = 0x02;
    protected const ASN1_SEQUENCE = 0x10;

    protected EcdsaPublicKey $publicKey;

    public function __construct(EcdsaPublicKey $publicKey)
    {
        $this->publicKey = $publicKey;
    }

    /**
     * @inheritdoc
     */
    public function verify(string $plain, string $signature): void
    {
        $signature = $this->signatureToDer($signature);
        if (openssl_verify($plain, $signature, $this->publicKey->getResource(), $this->algorithm()) !== 1) {
            throw new InvalidSignatureException(openssl_error_string() ?: "The signature is invalid.");
        }
    }

    protected function signatureToDer(string $signature): string
    {
        $length = max(1, (int)(strlen($signature) / 2));
        [$r, $s] = str_split($signature, $length);

        $r = ltrim($r, "\x00");
        $s = ltrim($s, "\x00");

        if (ord($r[0]) > 0x7f) {
            $r = "\x00" . $r;
        }
        if (ord($s[0]) > 0x7f) {
            $s = "\x00" . $s;
        }

        return $this->encodeDer(
            self::ASN1_SEQUENCE,
            $this->encodeDer(self::ASN1_INTEGER, $r) . $this->encodeDer(self::ASN1_INTEGER, $s),
        );
    }

    protected function encodeDer(int $type, string $value): string
    {
        $tagHeader = 0;
        if ($type === self::ASN1_SEQUENCE) {
            $tagHeader |= 0x20;
        }

        $der = chr($tagHeader | $type);
        $der .= chr(strlen($value));

        return $der . $value;
    }

    /**
     * @inheritDoc
     */
    public function kid(): ?string
    {
        return $this->publicKey->getId();
    }

    public function getPublicKey(): EcdsaPublicKey
    {
        return $this->publicKey;
    }
}
