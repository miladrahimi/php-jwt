<?php declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography\Algorithms\Ecdsa;

use MiladRahimi\Jwt\Cryptography\Verifier;
use function chr;
use function ltrim;
use function ord;
use function str_split;
use function strlen;

abstract class AbstractEcdsaVerifier implements Verifier
{
    use Naming;

    private const ASN1_INTEGER = 0x02;
    private const ASN1_SEQUENCE = 0x10;
    private const ASN1_BIT_STRING = 0x03;

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
}
