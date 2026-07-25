<?php

declare(strict_types=1);

namespace MiladRahimi\Jwt\Tests\Cryptography\Algorithms\RsaPss;

/**
 * Fixed test-only RSA keys whose modulus sizes are not multiples of eight bits, generated once with
 * `openssl genrsa <bits>`. They pin down the EMSA-PSS paths that common byte-aligned keys never reach:
 * 2047 bits leaves two excess bits to clear instead of one, 2041 bits makes the encoded message one byte
 * shorter than the modulus, and 2042 bits changes the encoded-message length arithmetic by one bit.
 * The RSA-PSS tests hold OpenSSL CLI signature vectors for these keys — regenerate those together if the
 * keys ever change.
 */
final class KeyFixtures
{
    public const PRIVATE_KEY_2047 = <<<'EOT'
-----BEGIN PRIVATE KEY-----
MIIEugIBADANBgkqhkiG9w0BAQEFAASCBKQwggSgAgEAAoIBAGi9hhYaBVkKeE7k
yVRIsL0llkkGV0LrIEEYoCuImkG/iHE5j45fW7PZUt4q3D4OcVNIR5LdI/5jqYaa
b2gccMjeKxEZimhj/3jttOFZNXHlBEQb9rlzIDU8PNo/Yx1+CmLFVUre8NUSczMn
vF/LfSCVels9dWCP3TuCkcrhiwDq85luFok54JEPENGylTU3VtpdkntG8QC6RNN0
/Ipl4NKBEVBj1Vv6+jAgn88xwNAXQwnOXkLGs1yRect7WF89bAmcTdhS7KmsmxIG
qNrtIdJv6+N82Wc24GwcKbs0r5pAUXcyX6sr7LTz+n22nlGZ3kOevZCtHo1aVS5v
3vvARm0CAwEAAQKCAQA7LXmo2yLSYBwBVzp5KGjTNX1n3PFImdgrb2JvtkqRg0nv
zvnREweY4dz0MXsmhLp6t4fY7qD7hguuRWtUg10l4ICstKWCvZ0GEif0epa7tw1l
/fa0aNt1uIcZOF8jtqbfj2bVWojvmfEEohrIdQxJcKslCeBbomz4xpjg6/XBmjlN
vIS0yMJioPfUtnLJoVIFCHXJFBy2u0IBgGWGnmHkBV3VUt8QY9TD/oFwQY1opa6x
ZcLVqRFEFD+27f921ICWObfqj4LSWGIxvu3TCeDAymVhQqtfp7DAW7GyyKdyBb97
RlDnbPcizZuvGlWAUefJuJJxcjqc7hp+F1rtNPnxAoGBAOjj4bNWzxAzNeRHZPwi
S7S53mkP+BnyfNARyWPiTvbHbz40Ud1S7xDyw0t0nK6OuQa6EUMiL8iHmYHgb3ld
wfK+kv8jb4x+M9x7km02/uvee4SAlTj5qWsISfHsRLyktNkuDQhVtwpC1RWZqb87
vRckyCKTXIPMUPy3v6r40t0jAoGAcyI/IYIGbtUgsyblbQwIni8GpovYMFVJCc90
EoKeMp7OceJ14f/mg43tigM6WiuOBw4HItjTfRcGfRTZN/44I3YpbW3Y23gxARw9
bJpybfaIUGhaOTtksVFDAet18tR9N58x7D4aYWkLdplJGWsnXKb66jvrqg2NX5HO
CR1y7y8CgYALy1an1XKhGGbXS8JSfo4k9fDMk1F2RvCJPQ1c8J4dI1Z/6PhoZAXV
buXzEVHKCVJXg97R7o5K8osUp8AdfmEPIRWitDG3BMEtnlh5DXr1iQvqVvS3sPUi
hYXxKY0FnLXH9ewVCvo9G8tcz65oD+dwn50/GwVpa1SCp++eAgHzzwKBgEh7JNdJ
bhdUITPnpsORsdMzs7Ihk8ZJyqNccKw+gq1HgJv9f0z5tvrW3NXn1lJx3QXf9Ooh
KnMzjags+drgNiNM/iOf5ce00NTsHFdEnAlSDNrh9vrUwz1F9TM+MpDe6L2dgOZC
6oSshsTxFy3jYXJYxNm1Q1VZFsk1l0nxuiuNAoGAVEZgWa00Mkw1GnUpdCpfeOsw
4UrUlE4lXkdvZjRC9cMMbTci7X70UaWrrPV4oVygoeLRjT+6PH9b27G2vMoxC1sD
E5SThI973xSB91WU5XcNJip99Bl1lFVQwA8BbyjHt30vuEBE3jfRVWmgoQfDTRlj
9XGYvpO/v2W7nzznQDg=
-----END PRIVATE KEY-----
EOT;

    public const PUBLIC_KEY_2047 = <<<'EOT'
-----BEGIN PUBLIC KEY-----
MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQBovYYWGgVZCnhO5MlUSLC9
JZZJBldC6yBBGKAriJpBv4hxOY+OX1uz2VLeKtw+DnFTSEeS3SP+Y6mGmm9oHHDI
3isRGYpoY/947bThWTVx5QREG/a5cyA1PDzaP2MdfgpixVVK3vDVEnMzJ7xfy30g
lXpbPXVgj907gpHK4YsA6vOZbhaJOeCRDxDRspU1N1baXZJ7RvEAukTTdPyKZeDS
gRFQY9Vb+vowIJ/PMcDQF0MJzl5CxrNckXnLe1hfPWwJnE3YUuyprJsSBqja7SHS
b+vjfNlnNuBsHCm7NK+aQFF3Ml+rK+y08/p9tp5Rmd5Dnr2QrR6NWlUub977wEZt
AgMBAAE=
-----END PUBLIC KEY-----
EOT;

    public const PRIVATE_KEY_2041 = <<<'EOT'
-----BEGIN PRIVATE KEY-----
MIIEuQIBADANBgkqhkiG9w0BAQEFAASCBKMwggSfAgEAAoIBAAGGzVR48Nl7bt2T
CK/YcmyNz4MECx6CwNldeXvyaLS8Z8/wRUZEOPycxluKryEruI5ymxA43QS1GyM1
B01MEi1J77i4kNYeu0jWUSSzWWw1U4BvbjadkQ+/dbqnOamJ4wOrvXnjg2dOIipi
q5lvsWOD63/VvsJu20l6s5cQMJ6ddJXf5IiyrxUxMLTlyXhkllTRhnaFfqoS7bp2
rQjiaJ+d1WGsZzgGv9ljI6+J7vjZisalBwHbfabaQGsC2F1T7fZ5+M6jC11Xw5W0
UokfN3fKgZzJH7pxCwM6zUuFMc4CKLr6AcoqlYTc6wy9MLDA+Sp8UqTRc33Kf8VX
EvYNFysCAwEAAQKCAQAAnHiZ2dKVQVaiYLyZq5Ak5qKvUm8hSDjuzv5VIjnKI6Vt
HEagW7B1dE/3Vw/HuDmszzZGyH215M14y0KhMFQWzgOtcjiLgsJ551WV3DlxmehV
BEiclXn/VClPEqWDvDGoxpqWswFp217Sma8bQB1GOwuPo4U9VCV4xigh09mjqFaS
dHtejDCjAhZdRgMH9TioLp1JeAGk1uFz/3d9lqZllziTdoiFN38qWn91JfUFP6uc
JA4frMjT3Rzpjn4ClHasdqr9YBp5Gv1npyhpiYyfkurAACliJ1xdaNzhKxaPlDbs
CwBjsUol3XJTcOL8/l+11XAE8Cen326XkwAQHCgBAoGAHLt6MdepsFnV4uoGfLBy
oBVsaQQLNosnGVdI4d76wT6rL182W+baz1oGyQ43Caeta6YvdSSvGpBk81g5sCtd
QL5/NHDyKGxZnLlg1CdQ8NkfkvHmZw2zhY1P4cqg06ZAzz9pfi/+LUX6WgIaTFje
5dg0cbUGaJ9WwRa3B+Q2bYkCgYANmforA2GCpGI8oMLjH291Vh1BvTJeUUHvIUv2
5lUyB67rhl9LC905OI3lt2/UqVJba9uOtKNAHZSrSo6z5Fvkx8V3DujZVF+mNeGy
qv8TBMKO84VIkvoaBNod+zHfdMMoxxjScbpSKoSsCasaN7a2Zv3U0OJVj7W2B0Xm
gzPGEwKBgAC+6PQEOfZGzqNeGZ8A4WjARZkQLs5SnEgvGMgsBmwfmUfYe8u02TcK
iiSLxufsPzcNECxFMHpLByO9xXmKFpiImTqeN9rOvSCxOw8mmhY2PHiO6MEB/QfZ
XBprLPNxXDtE1RMeYcWBDHdrmI0kvVxP2USeQzVR9Wl7knKU/MipAoGABiVWSgtM
C0kV7olBpnj01xMjQyonUUDsRw5Hkfe/9UxNeLUN6A4jVxC75Vm+2VvtD8wruE7d
GUKEg+W7l4OPFlBCZKrDAjjCw4rDQgVMHp7e/tMAnat0AT/CAxwXC/5plMpp5+Vl
qGz35/iybLVSBReCiKAeNUUreWXN6vvL8CsCgYAUJatcc5HbFyJZde1tKHJuUfPD
3M2MCVteKNPoi+uMDyVBqSbX16GjmweZ5uGoG0cIj3FRq2PfLaY/jpqyeetDTpFw
pj8rKjq/jrUhqFAeU49f+EE9Qfau4jjR+e+b6/G8Fg6iCo4vR+d4uEpPLbQAWjTd
OMjffT5i4WXTzx93aw==
-----END PRIVATE KEY-----
EOT;

    public const PUBLIC_KEY_2041 = <<<'EOT'
-----BEGIN PUBLIC KEY-----
MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQABhs1UePDZe27dkwiv2HJs
jc+DBAsegsDZXXl78mi0vGfP8EVGRDj8nMZbiq8hK7iOcpsQON0EtRsjNQdNTBIt
Se+4uJDWHrtI1lEks1lsNVOAb242nZEPv3W6pzmpieMDq71544NnTiIqYquZb7Fj
g+t/1b7CbttJerOXEDCenXSV3+SIsq8VMTC05cl4ZJZU0YZ2hX6qEu26dq0I4mif
ndVhrGc4Br/ZYyOvie742YrGpQcB232m2kBrAthdU+32efjOowtdV8OVtFKJHzd3
yoGcyR+6cQsDOs1LhTHOAii6+gHKKpWE3OsMvTCwwPkqfFKk0XN9yn/FVxL2DRcr
AgMBAAE=
-----END PUBLIC KEY-----
EOT;

    public const PUBLIC_KEY_2042 = <<<'EOT'
-----BEGIN PUBLIC KEY-----
MIIBITANBgkqhkiG9w0BAQEFAAOCAQ4AMIIBCQKCAQADGFOB0l4EqJs/aKAA907D
+adODHRUuY18607kdjVNxiFI263FGELYvJQFlSfG/NZm/kjWmacBI8RfhDBKF98o
Yt1Gc422rUo77JGfdYaSMRd0A8iOVRqrNtb5iykJLgWd0YUYAVqd36IfsjMPC2I5
Wl8aeG6ZNL6w2SBgYv0MBK41OtpAGVn7Godd/iBH6D0Lb21UitljHfW97S+Yr2Fj
UjRhJviTh8BnBTRfmBF6XeM9RQiOKUfUHiYCzqjxf+EYM7PP1BnCiOVgdD8jvv7q
XI9gJ0i09jI+emL6bg5sMI0weCqLmZtsKt82Fz+VYGgH0XVJ6RjY/DOPjDf2wsF/
AgMBAAE=
-----END PUBLIC KEY-----
EOT;

    private function __construct()
    {
    }
}
