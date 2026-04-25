<?php

declare(strict_types=1);

namespace Ubxty\UbxCert\Acme;

use OpenSSLAsymmetricKey;
use RuntimeException;

/**
 * JWS / JWK helper for ACME v2 protocol.
 *
 * Handles:
 *  - RSA 4096 key generation and persistence
 *  - JWK (JSON Web Key) representation
 *  - Key thumbprint for DNS-01 TXT value computation
 *  - JWS (JSON Web Signature) request signing
 */
class JwsHelper
{
    private ?OpenSSLAsymmetricKey $key = null;
    private ?string $thumbprint = null;

    private function __construct(private readonly string $keyPath) {}

    public static function load(string $keyPath): self
    {
        $helper = new self($keyPath);
        $helper->loadKey();
        return $helper;
    }

    public static function generate(string $keyPath): self
    {
        $helper = new self($keyPath);
        $helper->generateKey();
        return $helper;
    }

    /** Load if key exists, generate if not */
    public static function loadOrGenerate(string $keyPath): self
    {
        return file_exists($keyPath) ? self::load($keyPath) : self::generate($keyPath);
    }

    // -------------------------------------------------------------------------
    // Key management
    // -------------------------------------------------------------------------

    private function generateKey(): void
    {
        $key = openssl_pkey_new([
            'private_key_bits' => 4096,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        if ($key === false) {
            throw new RuntimeException('Failed to generate RSA key: ' . openssl_error_string());
        }

        $dir = dirname($this->keyPath);
        if (!is_dir($dir)) {
            mkdir($dir, 0700, true);
        }

        openssl_pkey_export($key, $pem);
        file_put_contents($this->keyPath, $pem);
        chmod($this->keyPath, 0600);

        $this->key = $key;
        $this->thumbprint = null;
    }

    private function loadKey(): void
    {
        if (!file_exists($this->keyPath)) {
            throw new RuntimeException("Key file not found: {$this->keyPath}");
        }

        $pem = file_get_contents($this->keyPath);
        $key = openssl_pkey_get_private($pem);

        if ($key === false) {
            throw new RuntimeException("Failed to load private key: {$this->keyPath}");
        }

        $this->key = $key;
        $this->thumbprint = null;
    }

    // -------------------------------------------------------------------------
    // JWK / Thumbprint
    // -------------------------------------------------------------------------

    /** Build the JWK object for the account key (public key only) */
    public function getJwk(): array
    {
        $details = openssl_pkey_get_details($this->key);

        if ($details === false || !isset($details['rsa'])) {
            throw new RuntimeException('Failed to get RSA key details.');
        }

        return [
            'e'   => self::base64url($details['rsa']['e']),
            'kty' => 'RSA',
            'n'   => self::base64url($details['rsa']['n']),
        ];
    }

    /**
     * RFC 7638 JWK thumbprint — used in DNS-01 key authorization.
     * Keys MUST be in alphabetical order and no extra whitespace.
     */
    public function getThumbprint(): string
    {
        if ($this->thumbprint !== null) {
            return $this->thumbprint;
        }

        $jwk = $this->getJwk();
        // Canonical JSON: alphabetical keys, no extra whitespace
        $canonical = json_encode(['e' => $jwk['e'], 'kty' => $jwk['kty'], 'n' => $jwk['n']], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);

        $this->thumbprint = self::base64url(hash('sha256', $canonical, true));
        return $this->thumbprint;
    }

    /**
     * Compute the DNS TXT value for a DNS-01 challenge token.
     *  key_authorization = token + "." + thumbprint
     *  txt_value         = base64url(sha256(key_authorization))
     */
    public function computeDnsTxtValue(string $token): string
    {
        $keyAuth = $token . '.' . $this->getThumbprint();
        return self::base64url(hash('sha256', $keyAuth, true));
    }

    // -------------------------------------------------------------------------
    // JWS signing
    // -------------------------------------------------------------------------

    /**
     * Build and sign a JWS request body for ACME.
     *
     * @param  string      $url     Target ACME endpoint URL
     * @param  array|null  $payload Payload data; null = POST-as-GET
     * @param  string      $nonce   Fresh replay nonce
     * @param  string|null $kid     Account URL (null when creating account)
     */
    public function sign(string $url, ?array $payload, string $nonce, ?string $kid): string
    {
        $header = ['alg' => 'RS256', 'nonce' => $nonce, 'url' => $url];

        if ($kid !== null) {
            $header['kid'] = $kid;
        } else {
            $header['jwk'] = $this->getJwk();
        }

        $protectedHeader = self::base64url(json_encode($header, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE));

        // POST-as-GET = empty string payload; empty object `{}` = trigger challenge
        if ($payload === null) {
            $encodedPayload = '';
        } else {
            // An empty PHP array encodes as "[]" but ACME requires "{}" for challenge trigger (RFC 8555 §7.5.1)
            $encodedPayload = self::base64url(json_encode(
                empty($payload) ? (object) [] : $payload,
                JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE
            ));
        }

        $signingInput = "{$protectedHeader}.{$encodedPayload}";

        if (!openssl_sign($signingInput, $signature, $this->key, OPENSSL_ALGO_SHA256)) {
            throw new RuntimeException('Failed to sign JWS: ' . openssl_error_string());
        }

        return json_encode([
            'protected' => $protectedHeader,
            'payload'   => $encodedPayload,
            'signature' => self::base64url($signature),
        ]);
    }

    // -------------------------------------------------------------------------
    // Utilities
    // -------------------------------------------------------------------------

    public static function base64url(string $data): string
    {
        return rtrim(strtr(base64_encode($data), '+/', '-_'), '=');
    }

    public static function base64urlDecode(string $data): string
    {
        return base64_decode(str_pad(strtr($data, '-_', '+/'), strlen($data) % 4, '=', STR_PAD_RIGHT));
    }
}
