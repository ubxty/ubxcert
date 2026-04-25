<?php

declare(strict_types=1);

namespace Ubxty\UbxCert\Cert;

use OpenSSLAsymmetricKey;
use RuntimeException;
use Ubxty\UbxCert\State\StateManager;

/**
 * Certificate lifecycle management.
 *
 * Responsibilities:
 *  - Generate certificate private keys
 *  - Generate CSRs with proper SANs
 *  - Parse and split PEM chain into cert + chain + fullchain
 *  - Write certificate files to /etc/ubxcert/certs/{domain}/
 *  - Create /etc/letsencrypt/live/{domain}/ symlinks for backward compatibility
 *  - Check expiry and renewal need
 */
class CertificateManager
{
    public function __construct(private readonly StateManager $state) {}

    // -------------------------------------------------------------------------
    // Key generation
    // -------------------------------------------------------------------------

    public function generateCertKey(string $domain): OpenSSLAsymmetricKey
    {
        $key = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);

        if ($key === false) {
            throw new RuntimeException('Failed to generate certificate key: ' . openssl_error_string());
        }

        $keyPath = $this->state->getOrderCertKeyPath($domain);
        $dir = dirname($keyPath);
        if (!is_dir($dir)) {
            mkdir($dir, 0700, true);
        }

        openssl_pkey_export($key, $pem);
        file_put_contents($keyPath, $pem);
        chmod($keyPath, 0600);

        return $key;
    }

    public function loadCertKey(string $domain): OpenSSLAsymmetricKey
    {
        $keyPath = $this->state->getOrderCertKeyPath($domain);

        if (!file_exists($keyPath)) {
            throw new RuntimeException("Certificate key not found: {$keyPath}");
        }

        $key = openssl_pkey_get_private(file_get_contents($keyPath));
        if ($key === false) {
            throw new RuntimeException("Failed to load certificate key: {$keyPath}");
        }

        return $key;
    }

    // -------------------------------------------------------------------------
    // CSR generation
    // -------------------------------------------------------------------------

    /**
     * Generate a CSR for the given domains.
     * Returns the CSR in DER (binary) format for ACME finalize.
     *
     * @param  string[] $domains  e.g. ['*.example.com', 'example.com']
     */
    public function generateCsr(array $domains, OpenSSLAsymmetricKey $privkey): string
    {
        $primaryDomain = ltrim($domains[0], '*.');
        $san           = implode(',', array_map(fn($d) => "DNS:{$d}", $domains));

        // PHP's openssl_csr_new() needs a config file to set subjectAltName
        $tmpConfig = tempnam(sys_get_temp_dir(), 'ubxcert_csr_');

        try {
            file_put_contents($tmpConfig, implode("\n", [
                '[req]',
                'distinguished_name = req_dn',
                'req_extensions     = req_ext',
                'prompt             = no',
                '',
                '[req_dn]',
                "CN = {$primaryDomain}",
                '',
                '[req_ext]',
                "subjectAltName = {$san}",
            ]));

            $dn  = ['CN' => $primaryDomain];
            $csr = openssl_csr_new($dn, $privkey, [
                'config'         => $tmpConfig,
                'digest_alg'     => 'sha256',
                'req_extensions' => 'req_ext',
            ]);

            if ($csr === false) {
                throw new RuntimeException('Failed to generate CSR: ' . openssl_error_string());
            }

            // Export to PEM, then convert to DER (ACME requires DER)
            openssl_csr_export($csr, $csrPem);
        } finally {
            @unlink($tmpConfig);
        }

        // Strip PEM header/footer and decode to binary DER
        $csrPem  = trim($csrPem);
        $lines   = explode("\n", $csrPem);
        $derLines = [];
        foreach ($lines as $line) {
            $line = trim($line);
            if ($line === '-----BEGIN CERTIFICATE REQUEST-----' || $line === '-----END CERTIFICATE REQUEST-----') {
                continue;
            }
            $derLines[] = $line;
        }

        return base64_decode(implode('', $derLines));
    }

    // -------------------------------------------------------------------------
    // Certificate storage
    // -------------------------------------------------------------------------

    /**
     * Split a PEM chain and save individual files.
     * Creates /etc/ubxcert/certs/{domain}/ with:
     *   cert.pem, chain.pem, fullchain.pem, privkey.pem
     * Also creates /etc/letsencrypt/live/{domain}/ symlinks.
     */
    public function saveCertificate(string $domain, string $fullChainPem, OpenSSLAsymmetricKey $privkey): void
    {
        $certDir = $this->state->getCertDir($domain);
        if (!is_dir($certDir)) {
            mkdir($certDir, 0700, true);
        }

        [$certPem, $chainPem] = $this->splitChain($fullChainPem);

        openssl_pkey_export($privkey, $privkeyPem);

        file_put_contents($certDir . '/cert.pem',      $certPem);
        file_put_contents($certDir . '/chain.pem',     $chainPem);
        file_put_contents($certDir . '/fullchain.pem', $fullChainPem);
        file_put_contents($certDir . '/privkey.pem',   $privkeyPem);

        chmod($certDir . '/privkey.pem', 0600);

        $this->createLetsencryptSymlinks($domain, $certDir);
    }

    /**
     * Create /etc/letsencrypt/live/{domain}/ symlinks pointing to /etc/ubxcert/certs/{domain}/
     * This ensures backward compatibility with certbot consumers.
     */
    public function createLetsencryptSymlinks(string $domain, string $certDir): void
    {
        $liveDir = "/etc/letsencrypt/live/{$domain}";

        if (!is_dir($liveDir)) {
            @mkdir($liveDir, 0755, true);
        }

        $files = ['cert.pem', 'chain.pem', 'fullchain.pem', 'privkey.pem'];
        foreach ($files as $file) {
            $link   = "{$liveDir}/{$file}";
            $target = "{$certDir}/{$file}";

            if (is_link($link)) {
                unlink($link);
            } elseif (file_exists($link)) {
                // Backup existing certbot-managed file before replacing
                rename($link, "{$link}.certbot.bak");
            }

            symlink($target, $link);
        }
    }

    // -------------------------------------------------------------------------
    // Expiry / renewal checks
    // -------------------------------------------------------------------------

    /**
     * Return the expiry date as a Unix timestamp, or null if cert does not exist.
     */
    public function getCertExpiry(string $domain): ?int
    {
        $path = $this->state->getCertDir($domain) . '/cert.pem';
        if (!file_exists($path)) {
            return null;
        }

        $cert = openssl_x509_read(file_get_contents($path));
        if ($cert === false) {
            return null;
        }

        $info = openssl_x509_parse($cert);
        return $info['validTo_time_t'] ?? null;
    }

    public function needsRenewal(string $domain, int $daysBeforeExpiry = 30): bool
    {
        $expiry = $this->getCertExpiry($domain);
        if ($expiry === null) {
            return true; // No cert = needs issuance
        }

        return $expiry < (time() + $daysBeforeExpiry * 86400);
    }

    /** Return a human-readable expiry string, e.g. "2025-07-01 03:00:00 UTC (67 days)" */
    public function getExpiryFormatted(string $domain): string
    {
        $expiry = $this->getCertExpiry($domain);
        if ($expiry === null) {
            return 'No certificate found';
        }

        $days = (int)(($expiry - time()) / 86400);
        $date = gmdate('Y-m-d H:i:s', $expiry) . ' UTC';
        return $days > 0 ? "{$date} ({$days} days)" : "{$date} (EXPIRED {$days} days ago)";
    }

    // -------------------------------------------------------------------------
    // Utilities
    // -------------------------------------------------------------------------

    /**
     * Split a PEM chain into [certificate, chain].
     * The first certificate is the leaf; the rest form the chain.
     */
    private function splitChain(string $fullChain): array
    {
        preg_match_all('/-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----/s', $fullChain, $matches);

        $certs = $matches[0] ?? [];
        if (empty($certs)) {
            throw new RuntimeException('Cannot parse certificate chain — no PEM blocks found.');
        }

        $certPem  = $certs[0] . "\n";
        $chainPem = count($certs) > 1 ? implode("\n", array_slice($certs, 1)) . "\n" : '';

        return [$certPem, $chainPem];
    }
}
