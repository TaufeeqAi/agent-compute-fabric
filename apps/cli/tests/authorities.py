"""Two certificate authorities that exist for the tests of ``ca_file``.

Each is a self-signed certificate made for this file and for nothing else. Only the certificates are
here: their private keys were never kept, so nothing can be signed in their names.
"""

from __future__ import annotations

from typing import Final

ONE_NAME: Final = "agent-compute test authority one"
TWO_NAME: Final = "agent-compute test authority two"

ONE: Final = """\
-----BEGIN CERTIFICATE-----
MIIBrTCCAVOgAwIBAgIULsHpRCeAOoWPXyr4Qclgxf+wRsQwCgYIKoZIzj0EAwIw
KzEpMCcGA1UEAwwgYWdlbnQtY29tcHV0ZSB0ZXN0IGF1dGhvcml0eSBvbmUwIBcN
MjYxMTE5MjIyMzM0WhgPMjEyNjEwMjYyMjIzMzRaMCsxKTAnBgNVBAMMIGFnZW50
LWNvbXB1dGUgdGVzdCBhdXRob3JpdHkgb25lMFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAE72HvIDH2E+Qb1dmZb+xfft8H6W9qXQKKSu6tCXTbvYG8u8DlPfPTjROG
pxYweEp3ptOv6eTU0MLpk0nDoHZ+HqNTMFEwHQYDVR0OBBYEFMYTfuaw48DmvRfK
svmq6kBaPmJEMB8GA1UdIwQYMBaAFMYTfuaw48DmvRfKsvmq6kBaPmJEMA8GA1Ud
EwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDSAAwRQIhAPyZ2BYxYtzS7XwVO85BT+3T
bHQx3Q3j7E05WcvNF4IiAiBsro9+AP/hp8Gt5Kq5zlmMdL+BulItU+Tx16Ew/2Dt
gA==
-----END CERTIFICATE-----
"""

TWO: Final = """\
-----BEGIN CERTIFICATE-----
MIIBrDCCAVOgAwIBAgIUDXuxIBsrRP5/hG7V6KZItuj0q+cwCgYIKoZIzj0EAwIw
KzEpMCcGA1UEAwwgYWdlbnQtY29tcHV0ZSB0ZXN0IGF1dGhvcml0eSB0d28wIBcN
MjYxMTE5MjIyMzM0WhgPMjEyNjEwMjYyMjIzMzRaMCsxKTAnBgNVBAMMIGFnZW50
LWNvbXB1dGUgdGVzdCBhdXRob3JpdHkgdHdvMFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEME8Uh783gVdlgB28UFUdLgZug/pLe0pUCMofoqRwZhbdNXdly1CNIAq5
hblZxcM9DUCtz2rma/+G1NVOK773M6NTMFEwHQYDVR0OBBYEFDUM00jpXA+6COov
zMmTpogN1+PbMB8GA1UdIwQYMBaAFDUM00jpXA+6COovzMmTpogN1+PbMA8GA1Ud
EwEB/wQFMAMBAf8wCgYIKoZIzj0EAwIDRwAwRAIgTpJUTaPgIuO+B6j9JChsQfTs
beMEmuzg3yqsYYxoJFgCIGxaOakDTiKrAOdbrPJ8vLHpk4/dRXb6r7ZIQaSyZljN
-----END CERTIFICATE-----
"""
