<?php

declare(strict_types=1);

namespace Ubxty\UbxCert\Acme;

use RuntimeException;

/**
 * Full ACME v2 protocol client.
 *
 * Implements:
 *  - Directory lookup and caching
 *  - Nonce management
 *  - Account creation / lookup (POST /new-acct)
 *  - Order creation (POST /new-order)
 *  - Authorization fetch (POST-as-GET /authz-*)
 *  - Challenge trigger (POST /chall-*)
 *  - Order status polling (POST-as-GET /order-*)
 *  - Order finalization (POST /finalize-*)
 *  - Certificate download (POST-as-GET /cert-*)
 */
class AcmeClient
{
    private const PRODUCTION_DIRECTORY = 'https://acme-v02.api.letsencrypt.org/directory';
    private const STAGING_DIRECTORY    = 'https://acme-staging-v02.api.letsencrypt.org/directory';

    private array $directory = [];
    private string $nonce    = '';

    public function __construct(private readonly bool $staging = false) {}

    // -------------------------------------------------------------------------
    // Directory & Nonce
    // -------------------------------------------------------------------------

    public function getDirectory(): array
    {
        if (!empty($this->directory)) {
            return $this->directory;
        }

        $response = $this->rawGet($this->staging ? self::STAGING_DIRECTORY : self::PRODUCTION_DIRECTORY);
        $data = json_decode($response['body'], true);

        if (!isset($data['newAccount'])) {
            throw new RuntimeException('Invalid ACME directory response: ' . $response['body']);
        }

        return $this->directory = $data;
    }

    public function newNonce(): string
    {
        $dir      = $this->getDirectory();
        $response = $this->rawHead($dir['newNonce']);

        if (!isset($response['headers']['replay-nonce'])) {
            throw new RuntimeException('No Replay-Nonce header from ACME server.');
        }

        return $this->nonce = $response['headers']['replay-nonce'];
    }

    // -------------------------------------------------------------------------
    // Account
    // -------------------------------------------------------------------------

    /**
     * Create a new account or return the existing one for this key.
     * Returns the account KID (URL) and whether it was newly created.
     *
     * @return array{kid: string, created: bool}
     */
    public function createOrFindAccount(JwsHelper $jws, string $email): array
    {
        $dir  = $this->getDirectory();
        $nonce = $this->currentNonce();

        $payload = [
            'termsOfServiceAgreed' => true,
            'contact' => ["mailto:{$email}"],
        ];

        $response = $this->postJws($dir['newAccount'], $payload, $nonce, $jws, null);

        if (!in_array($response['status'], [200, 201])) {
            throw new RuntimeException("Account create/find failed ({$response['status']}): " . $response['body']);
        }

        $kid = $response['headers']['location'] ?? null;
        if (!$kid) {
            throw new RuntimeException('No Location header in account response.');
        }

        $this->consumeNonce($response['headers']);

        return ['kid' => $kid, 'created' => $response['status'] === 201];
    }

    // -------------------------------------------------------------------------
    // Orders
    // -------------------------------------------------------------------------

    /**
     * Create a new certificate order.
     *
     * @param  string[] $domains e.g. ['*.example.com', 'example.com']
     * @return array{order_url: string, status: string, authorizations: string[], finalize: string}
     */
    public function newOrder(JwsHelper $jws, string $kid, array $domains): array
    {
        $dir  = $this->getDirectory();
        $nonce = $this->currentNonce();

        $identifiers = array_map(fn($d) => ['type' => 'dns', 'value' => $d], $domains);
        $payload = ['identifiers' => $identifiers];

        $response = $this->postJws($dir['newOrder'], $payload, $nonce, $jws, $kid);

        if ($response['status'] !== 201) {
            $body = json_decode($response['body'], true);
            throw new RuntimeException('New order failed: ' . ($body['detail'] ?? $response['body']));
        }

        $order = json_decode($response['body'], true);
        $order['order_url'] = $response['headers']['location'] ?? null;

        $this->consumeNonce($response['headers']);
        return $order;
    }

    /** Fetch an authorization object (POST-as-GET). */
    public function getAuthorization(JwsHelper $jws, string $kid, string $authzUrl): array
    {
        $response = $this->postJws($authzUrl, null, $this->currentNonce(), $jws, $kid);

        if ($response['status'] !== 200) {
            throw new RuntimeException("Get authorization failed ({$response['status']}): " . $response['body']);
        }

        $this->consumeNonce($response['headers']);
        return json_decode($response['body'], true);
    }

    /** Notify ACME that the challenge is ready for validation. */
    public function triggerChallenge(JwsHelper $jws, string $kid, string $challengeUrl): array
    {
        // ACME spec: POST with empty JSON object {} (not null/POST-as-GET)
        $response = $this->postJws($challengeUrl, [], $this->currentNonce(), $jws, $kid);

        if (!in_array($response['status'], [200, 202])) {
            throw new RuntimeException("Trigger challenge failed ({$response['status']}): " . $response['body']);
        }

        $this->consumeNonce($response['headers']);
        return json_decode($response['body'], true);
    }

    /** Poll order status (POST-as-GET). */
    public function getOrderStatus(JwsHelper $jws, string $kid, string $orderUrl): array
    {
        $response = $this->postJws($orderUrl, null, $this->currentNonce(), $jws, $kid);

        if ($response['status'] !== 200) {
            throw new RuntimeException("Order status failed ({$response['status']}): " . $response['body']);
        }

        $order = json_decode($response['body'], true);
        $order['order_url'] = $orderUrl;

        $this->consumeNonce($response['headers']);
        return $order;
    }

    /**
     * Finalize order with a CSR (DER binary).
     * Returns the updated order object.
     */
    public function finalizeOrder(JwsHelper $jws, string $kid, string $finalizeUrl, string $csrDer): array
    {
        $payload  = ['csr' => JwsHelper::base64url($csrDer)];
        $response = $this->postJws($finalizeUrl, $payload, $this->currentNonce(), $jws, $kid);

        if (!in_array($response['status'], [200, 201])) {
            $body = json_decode($response['body'], true);
            throw new RuntimeException('Finalize order failed: ' . ($body['detail'] ?? $response['body']));
        }

        $this->consumeNonce($response['headers']);
        return json_decode($response['body'], true);
    }

    /** Download the issued certificate chain (PEM format). */
    public function downloadCertificate(JwsHelper $jws, string $kid, string $certUrl): string
    {
        $response = $this->postJws(
            $certUrl,
            null,
            $this->currentNonce(),
            $jws,
            $kid,
            'application/pem-certificate-chain'
        );

        if ($response['status'] !== 200) {
            throw new RuntimeException("Download certificate failed ({$response['status']}): " . $response['body']);
        }

        $this->consumeNonce($response['headers']);
        return $response['body'];
    }

    /** Revoke a certificate. $certDer = DER binary of the certificate. */
    public function revokeCertificate(JwsHelper $jws, string $kid, string $certDer, int $reason = 0): void
    {
        $dir     = $this->getDirectory();
        $payload = ['certificate' => JwsHelper::base64url($certDer), 'reason' => $reason];
        $response = $this->postJws($dir['revokeCert'], $payload, $this->currentNonce(), $jws, $kid);

        if (!in_array($response['status'], [200, 204])) {
            throw new RuntimeException("Revoke failed ({$response['status']}): " . $response['body']);
        }

        $this->consumeNonce($response['headers']);
    }

    // -------------------------------------------------------------------------
    // HTTP helpers
    // -------------------------------------------------------------------------

    private function currentNonce(): string
    {
        return $this->nonce ?: $this->newNonce();
    }

    private function consumeNonce(array $headers): void
    {
        if (isset($headers['replay-nonce'])) {
            $this->nonce = $headers['replay-nonce'];
        } else {
            // Nonce consumed; next call will fetch a fresh one
            $this->nonce = '';
        }
    }

    private function postJws(
        string     $url,
        ?array     $payload,
        string     $nonce,
        JwsHelper  $jws,
        ?string    $kid,
        string     $accept = 'application/json'
    ): array {
        $body = $jws->sign($url, $payload, $nonce, $kid);

        return $this->rawPost($url, $body, [
            'Content-Type: application/jose+json',
            "Accept: {$accept}",
        ]);
    }

    private function rawGet(string $url): array
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER         => true,
            CURLOPT_TIMEOUT        => 30,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_USERAGENT      => 'ubxcert/1.0 (+https://github.com/ubxty/ubxcert)',
        ]);

        $raw      = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $hSize    = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $error    = curl_error($ch);
        curl_close($ch);

        if ($raw === false) {
            throw new RuntimeException("cURL GET error: {$error}");
        }

        return $this->parseResponse($raw, $httpCode, $hSize);
    }

    private function rawHead(string $url): array
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER         => true,
            CURLOPT_NOBODY         => true,
            CURLOPT_TIMEOUT        => 30,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_USERAGENT      => 'ubxcert/1.0 (+https://github.com/ubxty/ubxcert)',
        ]);

        $raw      = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $hSize    = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $error    = curl_error($ch);
        curl_close($ch);

        if ($raw === false) {
            throw new RuntimeException("cURL HEAD error: {$error}");
        }

        return $this->parseResponse($raw, $httpCode, $hSize);
    }

    private function rawPost(string $url, string $body, array $headers = []): array
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_HEADER         => true,
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => $body,
            CURLOPT_HTTPHEADER     => $headers,
            CURLOPT_TIMEOUT        => 30,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_USERAGENT      => 'ubxcert/1.0 (+https://github.com/ubxty/ubxcert)',
        ]);

        $raw      = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $hSize    = curl_getinfo($ch, CURLINFO_HEADER_SIZE);
        $error    = curl_error($ch);
        curl_close($ch);

        if ($raw === false) {
            throw new RuntimeException("cURL POST error: {$error}");
        }

        return $this->parseResponse($raw, $httpCode, $hSize);
    }

    private function parseResponse(string $raw, int $status, int $headerSize): array
    {
        $headerBlock = substr($raw, 0, $headerSize);
        $body        = substr($raw, $headerSize);

        $headers = [];
        foreach (explode("\r\n", $headerBlock) as $line) {
            if (str_contains($line, ':')) {
                [$key, $value]                  = explode(':', $line, 2);
                $headers[strtolower(trim($key))] = trim($value);
            }
        }

        return ['status' => $status, 'headers' => $headers, 'body' => $body];
    }
}
