<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Cryptography\Algorithms\Ecdsa;

use MiladRahimi\Jwt\Cryptography\Keys\EcdsaPrivateKey;
use MiladRahimi\Jwt\Cryptography\Signer;
use MiladRahimi\Jwt\Exceptions\SigningException;

use function ltrim;
use function ord;
use function str_pad;
use function strlen;
use function substr;

abstract class AbstractEcdsaSigner implements Signer
{
    use Algorithm;

    protected const ASN1_BIT_STRING = 0x03;

    protected EcdsaPrivateKey $privateKey;

    public function __construct(EcdsaPrivateKey $privateKey)
    {
        $this->privateKey = $privateKey;
    }

    public function sign(string $message): string
    {
        if (openssl_sign($message, $signature, $this->privateKey->getResource(), $this->algorithm()) === true) {
            return $this->derToSignature($signature, $this->keySize());
        }

        throw new SigningException(openssl_error_string() ?: "OpenSSL cannot sign the token.");
    }

    protected function derToSignature(string $der, int $keySize): string
    {
        $i = $this->decodeDer($der)[0];
        [$i, $r] = $this->decodeDer($der, $i);
        $s = $this->decodeDer($der, $i)[1];

        $r = ltrim($r, "\x00");
        $s = ltrim($s, "\x00");

        $r = str_pad($r, $keySize / 8, "\x00", STR_PAD_LEFT);
        $s = str_pad($s, $keySize / 8, "\x00", STR_PAD_LEFT);

        return $r . $s;
    }

    protected function decodeDer(string $der, int $offset = 0): array
    {
        $pos = $offset;
        $size = strlen($der);
        $constructed = (ord($der[$pos]) >> 5) & 0x01;
        $type = ord($der[$pos++]) & 0x1f;

        $len = ord($der[$pos++]);
        if ($len & 0x80) {
            $n = $len & 0x1f;
            $len = 0;
            while ($n-- && $pos < $size) {
                $len = ($len << 8) | ord($der[$pos++]);
            }
        }

        if ($type === self::ASN1_BIT_STRING) {
            $pos++;
            $data = substr($der, $pos, $len - 1);
            $pos += $len - 1;
        } elseif (!$constructed) {
            $data = substr($der, $pos, $len);
            $pos += $len;
        } else {
            $data = '';
        }

        return [$pos, $data];
    }

    /**
     * @inheritDoc
     */
    public function kid(): ?string
    {
        return $this->privateKey->getId();
    }

    public function getPrivateKey(): EcdsaPrivateKey
    {
        return $this->privateKey;
    }
}
