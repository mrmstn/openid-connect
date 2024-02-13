<?php

namespace OpenIDConnect\Laravel;

use Illuminate\Config\Repository as Config;
use Laravel\Passport\Passport;

class JwksController
{
    public function jwks()
    {
        $publicKey = $this->getPublicKey();

        // Source: https://www.tuxed.net/fkooman/blog/json_web_key_set.html
        $keyInfo = openssl_pkey_get_details(openssl_pkey_get_public($publicKey));
        $keyDetails = [
            'kty' => 'RSA',
            'n' => $this->base64UrlEncode($keyInfo['rsa']['n']),
            'e' => $this->base64UrlEncode($keyInfo['rsa']['e']),
        ];
        $keyDetails = $this->addKid($keyDetails);

        $jsonData = [
            'keys' => [
                $keyDetails
            ],
        ];

        return response()->json($jsonData, 200, [], JSON_PRETTY_PRINT);
    }

    private function getPublicKey(): string
    {
        $publicKey = str_replace('\\n', "\n", app()->make(Config::class)->get('passport.public_key') ?? '');

        if (!$publicKey) {
            $publicKey = 'file://' . Passport::keyPath('oauth-public.key');
        }

        return $publicKey;
    }


    private function addKid(array $jwk): array
    {
        $thumbprint = $this->getJwkThumbprint($jwk);
        $jwk['kid'] = $thumbprint;
        return $jwk;
    }

    /**
     * @param array $jwk
     * @return string
     *
     * @see https://datatracker.ietf.org/doc/html/rfc7638
     */
    private function getJwkThumbprint(array $jwk): string
    {
        ksort($jwk); // Sort the keys to ensure that we generate always the same json.
        $canonicalJwk = json_encode($jwk, JSON_UNESCAPED_SLASHES);

        // Compute the SHA-256 hash of the canonical JWK
        $hash = hash('sha256', $canonicalJwk, true);

        // Base64url encode
        return $this->base64UrlEncode($hash);
    }

    private function base64UrlEncode($data): string
    {
        return rtrim(str_replace(['+', '/'], ['-', '_'], base64_encode($data)), '=');
    }
}
