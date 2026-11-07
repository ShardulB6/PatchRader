import type { PoolConfig } from "pg";

// Tiger Cloud signs service certificates with this private authority, which
// public root stores do not include. It is a public certificate, not a secret.
// SHA-256: 06:5A:75:0D:0D:64:F6:2D:AC:DC:97:9E:3B:83:D2:11:95:40:71:EA:59:B8:F3:40:7C:4E:87:CA:68:34:64:57
const TIGER_CLOUD_CA = `-----BEGIN CERTIFICATE-----
MIIBpzCCAUygAwIBAgIQfH0seuAygeQX2lTU/eVncDAKBggqhkjOPQQDAjAzMRYw
FAYDVQQKEw1UaW1lc2NhbGUgSW5jMRkwFwYDVQQDExBjYS50aW1lc2NhbGUuY29t
MB4XDTI1MDEyMzE1NDMzOVoXDTI3MTAyMDE1NDMzOVowMzEWMBQGA1UEChMNVGlt
ZXNjYWxlIEluYzEZMBcGA1UEAxMQY2EudGltZXNjYWxlLmNvbTBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABKRa3FQeN67oUZK6PdG7FtZKYSv1WgJrZ64mfX9pLNlE
EeVzCnHIAcE9xsQ5j/gccgu9oyiJ/CcLPlkzBHe34M2jQjBAMA4GA1UdDwEB/wQE
AwICpDAPBgNVHRMBAf8EBTADAQH/MB0GA1UdDgQWBBTZ/kgiRgLuL0Tg7eYuwBps
25fwzDAKBggqhkjOPQQDAgNJADBGAiEAvH4JAMgGPL/BSARg47GxjBKJ9Mz+Q3CI
i21+5khjUHECIQCH1kzoKAKTnrkCuifWW9K0CzqXPLSjJBIh3jH2aaWZFQ==
-----END CERTIFICATE-----
`;

export function poolConfig(databaseUrl: string): PoolConfig {
  // pg lets sslmode in the URL replace the ssl option, so remove it to keep the check below.
  const url = new URL(databaseUrl);
  url.searchParams.delete("sslmode");
  return {
    connectionString: url.toString(),
    ssl: { ca: TIGER_CLOUD_CA, rejectUnauthorized: true },
  };
}
