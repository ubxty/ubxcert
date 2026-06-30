<?php

declare(strict_types=1);

namespace Ubxty\UbxCert\Commands;

use Throwable;
use Ubxty\UbxCert\Acme\AcmeClient;
use Ubxty\UbxCert\Acme\JwsHelper;
use Ubxty\UbxCert\Util\WebrootChallenger;

/**
 * ubxcert complete
 *
 * Resumes a previously-created ACME order (from `ubxcert request`):
 *  1. Loads saved state from disk
 *  2. Optionally polls DNS (DNS-01) or the http-01 endpoint until ready
 *  3. Notifies ACME challenges are ready
 *  4. Polls order until 'ready' → finalizes → polls until 'valid'
 *  5. Downloads certificate chain and saves to /etc/ubxcert/certs/{domain}/
 *  6. Creates /etc/letsencrypt/live/{domain}/ symlinks for backward compat
 *
 * This step is fully resumable: re-running it after a crash simply
 * reloads the saved order state and continues where it left off.
 *
 * Usage:
 *   ubxcert complete --domain example.com [--wait-dns 600] [--staging] [--json]
 *   ubxcert complete --domain example.com --challenge http --wait-http 60
 */
class CompleteCommand extends BaseCommand
{
    private const POLL_INTERVAL_SECS  = 5;
    private const MAX_ORDER_POLLS     = 60; // 5 min max
    private const DNS_POLL_INTERVAL   = 10;
    private const HTTP_POLL_INTERVAL  = 5;
    private const DNS_RESOLVERS       = ['8.8.8.8', '1.1.1.1', '8.8.4.4'];

    public function getName(): string        { return 'complete'; }
    public function getDescription(): string { return 'Complete ACME challenge, finalize order, download certificate'; }

    public function run(array $args): int
    {
        $this->parseCommonArgs($args);

        $domain       = $this->extractOption($args, 'domain');
        $waitDns      = (int) ($this->extractOption($args, 'wait-dns') ?? 0);
        $waitHttp     = (int) ($this->extractOption($args, 'wait-http') ?? 0);
        $challengeOpt = $this->extractOption($args, 'challenge');
        $challenge    = $challengeOpt !== null ? strtolower($challengeOpt) : null;
        $explicitRoot = $this->extractOption($args, 'webroot');
        $autoWebroot  = !$this->hasFlag($args, 'no-auto-webroot');

        if (!$domain) {
            $this->fail('Usage: ubxcert complete --domain example.com [--wait-dns 600 | --wait-http 60 --challenge http] [--staging] [--json]');
            return 1;
        }

        if ($challenge !== null && !in_array($challenge, ['dns', 'http'], true)) {
            $this->fail("Invalid --challenge value '{$challenge}'. Use 'dns' or 'http'.");
            return 1;
        }

        if ($challenge === 'http' && $waitDns > 0) {
            $this->fail("--wait-dns is not compatible with --challenge http. Use --wait-http instead.");
            return 1;
        }

        // --- Load order state -----------------------------------------------
        $state = $this->state->loadOrderState($domain);

        if (!$state) {
            $this->fail("No pending order found for '{$domain}'. Run 'ubxcert request' first.");
            return 1;
        }

        // Resolve the actual challenge type in effect (state wins, flag may override sanity)
        $stateChallenge = $state['challenge_type'] ?? 'dns';

        if ($challenge !== null && $challenge !== $stateChallenge) {
            $this->fail("Order on disk was created with '{$stateChallenge}' challenge but --challenge '{$challenge}' was given. Use --force on 'request' to recreate, or omit the flag.");
            return 1;
        }

        $challenge = $stateChallenge;
        $isHttp    = $challenge === 'http';

        $this->out("Completing ACME order for: {$domain}");
        $this->out("Order status : {$state['order_status']}");
        $this->out("Challenge    : " . ($isHttp ? 'HTTP-01' : 'DNS-01'));

        // --- Auto-webroot (HTTP-01 only, default ON, idempotent) ----------
        // Files are only written if they do not already exist on disk, so a
        // re-`complete` after a manual `request` re-issue does not overwrite
        // a live file. Returns a map of token => docroot for shutdown cleanup.
        $autoWebrootDocroots = [];
        if ($isHttp && $autoWebroot) {
            $autoWebrootDocroots = $this->ensureWebrootFiles($state, $explicitRoot);
        }

        // --- Reconstruct ACME client ----------------------------------------
        $staging    = $state['staging'] ?? $this->staging;
        $kid        = $state['kid'];
        $accountJws = JwsHelper::load($this->state->getAccountKeyPath($state['email']));
        $client     = new AcmeClient($staging);

        // --- Wait for challenge propagation (optional) ----------------------
        if ($isHttp) {
            if ($waitHttp > 0) {
                $this->out("Waiting up to {$waitHttp}s for HTTP-01 challenge file to be served...");
                foreach ($state['challenges'] as &$challenge) {
                    if (($challenge['status'] ?? '') === 'valid') {
                        continue;
                    }
                    $ok = $this->waitForHttp(
                        $challenge['http_url'] ?? '',
                        $challenge['key_authorization'] ?? '',
                        $waitHttp
                    );
                    if (!$ok) {
                        $this->fail("HTTP-01 challenge file not reachable after {$waitHttp}s at {$challenge['http_url']}");
                        $this->fail("Expected body : {$challenge['key_authorization']}");
                        $this->fail("Serve the file at /.well-known/acme-challenge/<token> on the domain (port 80) and retry.");
                        return 1;
                    }
                    $this->success("HTTP-01 reachable for {$challenge['domain']}");
                }
                unset($challenge);
            } else {
                $this->verbose("Skipping HTTP-01 pre-check (no --wait-http given). ACME will validate on trigger.");
            }
        } else {
            if ($waitDns > 0) {
                $this->out("Waiting up to {$waitDns}s for DNS propagation...");
                foreach ($state['challenges'] as &$challenge) {
                    if (($challenge['status'] ?? '') === 'valid') {
                        continue;
                    }
                    $ok = $this->waitForDns(
                        $challenge['challenge_host'],
                        $challenge['txt_value'],
                        $waitDns
                    );
                    if (!$ok) {
                        $this->fail("DNS TXT record not visible after {$waitDns}s for {$challenge['challenge_host']}");
                        $this->fail("Expected value: {$challenge['txt_value']}");
                        $this->fail("Add the TXT record and retry.");
                        return 1;
                    }
                    $this->success("DNS verified for {$challenge['domain']}");
                }
                unset($challenge);
            }
        }

        // --- Trigger challenges that are still pending ----------------------
        foreach ($state['challenges'] as &$challenge) {
            if (($challenge['status'] ?? '') === 'valid') {
                $this->verbose("Challenge already valid for {$challenge['domain']}, skipping.");
                continue;
            }
            try {
                $this->verbose("Triggering challenge for {$challenge['domain']}...");
                $result = $client->triggerChallenge($accountJws, $kid, $challenge['challenge_url']);
                $challenge['status'] = $result['status'] ?? 'processing';
                $this->verbose("Challenge status: {$challenge['status']}");
            } catch (Throwable $e) {
                $this->fail("Failed to trigger challenge for {$challenge['domain']}: " . $e->getMessage());
                return 1;
            }
        }
        unset($challenge);

        // --- Poll order until 'ready' (all challenges valid) ----------------
        $this->out('Polling for authorization...');
        try {
            $order = $this->pollOrderUntil($client, $accountJws, $kid, $state['order_url'], ['ready', 'valid'], $state);
        } catch (Throwable $e) {
            $this->fail("Order polling failed: " . $e->getMessage());
            return 1;
        }

        if ($order['status'] === 'invalid') {
            $this->fail("ACME order is invalid. Challenges may have failed.");
            $this->displayOrderErrors($order);
            return 1;
        }

        $this->success("All challenges validated.");

        // --- Finalize order (submit CSR) ------------------------------------
        $this->out('Finalizing order (submitting CSR)...');
        try {
            $certKey = $this->certs->loadCertKey($domain);
            $csrDer  = $this->certs->generateCsr($state['domains'], $certKey);
            $order   = $client->finalizeOrder($accountJws, $kid, $state['finalize_url'], $csrDer);
        } catch (Throwable $e) {
            $this->fail("Finalization failed: " . $e->getMessage());
            return 1;
        }

        // --- Poll until 'valid' (cert ready for download) -------------------
        if ($order['status'] !== 'valid') {
            $this->out('Polling for certificate issuance...');
            try {
                $order = $this->pollOrderUntil($client, $accountJws, $kid, $state['order_url'], ['valid'], $state);
            } catch (Throwable $e) {
                $this->fail("Order final polling failed: " . $e->getMessage());
                return 1;
            }
        }

        if ($order['status'] !== 'valid') {
            $this->fail("Order did not become valid. Current status: {$order['status']}");
            return 1;
        }

        // --- Download certificate -------------------------------------------
        $certUrl = $order['certificate'] ?? null;

        if (!$certUrl) {
            $this->fail("No certificate URL in finalized order.");
            return 1;
        }

        $this->out('Downloading certificate...');
        try {
            $fullChain = $client->downloadCertificate($accountJws, $kid, $certUrl);
        } catch (Throwable $e) {
            $this->fail("Certificate download failed: " . $e->getMessage());
            return 1;
        }

        // --- Save cert files and create symlinks ----------------------------
        try {
            $certKey = $this->certs->loadCertKey($domain);
            $this->certs->saveCertificate($domain, $fullChain, $certKey);
            $this->certs->createLetsencryptSymlinks($domain, $this->state->getCertDir($domain));
        } catch (Throwable $e) {
            $this->fail("Saving certificate failed: " . $e->getMessage());
            return 1;
        }

        // --- Update state ---------------------------------------------------
        $state['order_status']    = 'valid';
        $state['certificate_url'] = $certUrl;
        $state['completed_at']    = date('c');
        $this->state->saveOrderState($domain, $state);

        // --- Schedule cleanup of auto-written challenge files ---------------
        // The cert is finalised; remove /.well-known/acme-challenge/<token>
        // on shutdown so the docroot doesn't accumulate stale tokens across
        // renew cycles. Best-effort, never fatal.
        if ($isHttp && !empty($autoWebrootDocroots)) {
            $this->scheduleWebrootCleanup($domain, $autoWebrootDocroots);
        }

        $expiry  = $this->certs->getExpiryFormatted($domain);
        $certDir = $this->state->getCertDir($domain);
        $this->log('info', "certificate issued for {$domain} expiry={$expiry}");

        if ($this->jsonMode) {
            $this->outputJson([
                'domain'           => $domain,
                'status'           => 'valid',
                'challenge_type'   => $challenge,
                'cert_dir'         => $certDir,
                'letsencrypt_live' => "/etc/letsencrypt/live/{$domain}",
                'fullchain_pem'    => "{$certDir}/fullchain.pem",
                'privkey_pem'      => "{$certDir}/privkey.pem",
                'expiry'           => $expiry,
                'auto_webroot'     => $isHttp ? array_keys($autoWebrootDocroots) : [],
            ]);
            return 0;
        }

        $this->out('');
        $this->success("Certificate issued and saved!");
        $this->out("  Cert dir   : {$certDir}");
        $this->out("  LE symlink : /etc/letsencrypt/live/{$domain}");
        $this->out("  Expiry     : {$expiry}");
        $this->out('');
        $this->out("Next step:  ubxcert install --domain {$domain} --webserver openresty|nginx|apache");

        return 0;
    }

    // -------------------------------------------------------------------------
    // DNS Polling
    // -------------------------------------------------------------------------

    private function waitForDns(string $host, string $expectedValue, int $timeout): bool
    {
        $start   = time();
        $attempt = 0;

        while ((time() - $start) < $timeout) {
            $attempt++;

            foreach (self::DNS_RESOLVERS as $resolver) {
                $output = shell_exec("dig +short TXT " . escapeshellarg($host) . " @{$resolver} 2>/dev/null");
                if ($output && str_contains($output, $expectedValue)) {
                    return true;
                }
            }

            if ($attempt % 6 === 0) {
                $elapsed = time() - $start;
                $this->out("  DNS poll {$attempt} ({$elapsed}s elapsed) — {$host}: not visible yet...");
            }

            sleep(self::DNS_POLL_INTERVAL);
        }

        return false;
    }

    // -------------------------------------------------------------------------
    // Auto-webroot
    // -------------------------------------------------------------------------

    /**
     * Idempotently ensure the HTTP-01 challenge file is in the
     * auto-detected docroot for every challenge in the order state.
     *
     * Skips any challenge whose file already exists at the resolved
     * path (so a manual `request` re-issue is preserved) and skips
     * with a warning when auto-detection cannot find a docroot
     * (the operator is expected to handle that case via
     * --webroot=… or manual serving).
     *
     * @return array<string, string>  map of token => docroot used (for cleanup)
     */
    private function ensureWebrootFiles(array $state, ?string $explicitRoot): array
    {
        $docrootByToken = [];
        $seen           = [];
        foreach ($state['challenges'] ?? [] as $c) {
            $token  = $c['token'] ?? null;
            $domain = $c['domain'] ?? null;
            if (!$token || !$domain) {
                continue;
            }
            if (isset($seen[$token])) {
                continue;
            }
            $seen[$token] = true;

            // Idempotency: if the file already exists, skip rewriting.
            // This lets the operator pre-write or hand-modify the file
            // without ubxcert clobbering it on every re-complete.
            $existingDocroot = WebrootChallenger::resolveDocrootFor($domain, $explicitRoot);
            if ($existingDocroot !== null && is_file($existingDocroot . '/.well-known/acme-challenge/' . $token)) {
                $this->verbose("HTTP-01 file already present at {$existingDocroot}/.well-known/acme-challenge/{$token}; skipping auto-write.");
                $docrootByToken[$token] = $existingDocroot;
                continue;
            }

            $result = WebrootChallenger::write(
                $domain,
                $token,
                $c['key_authorization'] ?? '',
                $explicitRoot,
                true
            );

            if ($result['wrote']) {
                $docrootByToken[$token] = $result['docroot'] ?? $explicitRoot ?? '';
                if ($result['verified']) {
                    $this->success("HTTP-01 auto-served for {$domain}: {$result['file_path']}");
                } else {
                    $this->out("\033[33mHTTP-01 file written for {$domain} but not yet reachable from outside: {$result['file_path']}\033[0m");
                    if (!empty($result['error'])) {
                        $this->out("\033[33m  " . $result['error'] . "\033[0m");
                    }
                }
            } else {
                $this->out("\033[33mHTTP-01 auto-webroot skipped for {$domain}: " . ($result['error'] ?? 'unknown') . "\033[0m");
            }
        }
        return $docrootByToken;
    }

    /**
     * Register a shutdown handler that removes the auto-written
     * challenge files. Best-effort — never fatal. Pass the
     * docroot map returned by ensureWebrootFiles() so we don't
     * need to re-resolve at shutdown (when vhost config may have
     * changed).
     *
     * @param array<string, string> $docrootByToken
     */
    private function scheduleWebrootCleanup(string $domain, array $docrootByToken): void
    {
        if (empty($docrootByToken)) {
            return;
        }
        register_shutdown_function(static function () use ($domain, $docrootByToken): void {
            foreach ($docrootByToken as $token => $docroot) {
                if ($docroot === '') {
                    continue;
                }
                WebrootChallenger::cleanup($domain, $token, $docroot);
            }
        });
    }

    // -------------------------------------------------------------------------
    // HTTP-01 Polling
    // -------------------------------------------------------------------------

    /**
     * Poll an HTTP-01 challenge URL until the response body matches the
     * expected key authorization, or the timeout is reached.
     *
     * Implementation notes:
     *  - Uses cURL (already a hard dep).
     *  - Treats the request as HTTP only; ACME requires port 80 for HTTP-01
     *    and the challenge must be served by the domain itself.
     *  - Comparison is a strict string equality after trim() — the spec
     *    requires the body to be exactly the key authorization.
     *  - Any reachable 2xx response with matching body is success.
     */
    private function waitForHttp(string $url, string $expectedKeyAuth, int $timeout): bool
    {
        if ($url === '' || $expectedKeyAuth === '') {
            return false;
        }

        $start   = time();
        $attempt = 0;

        while ((time() - $start) < $timeout) {
            $attempt++;

            $body = $this->fetchHttpBody($url);

            if ($body !== null && trim($body) === $expectedKeyAuth) {
                return true;
            }

            if ($attempt % 6 === 0) {
                $elapsed = time() - $start;
                $this->out("  HTTP poll {$attempt} ({$elapsed}s elapsed) — {$url}: not yet matching...");
            }

            sleep(self::HTTP_POLL_INTERVAL);
        }

        return false;
    }

    /**
     * GET an HTTP URL and return the body, or null on transport failure /
     * non-2xx status. Follows redirects.
     */
    private function fetchHttpBody(string $url): ?string
    {
        if (!function_exists('curl_init')) {
            $this->fail("ext-curl is required for HTTP-01 polling.");
            return null;
        }

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS      => 5,
            CURLOPT_TIMEOUT        => 15,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_HTTP_VERSION   => CURL_HTTP_VERSION_1_1,
            CURLOPT_USERAGENT      => 'ubxcert/1.0 (+https://github.com/ubxty/ubxcert) HTTP-01-poller',
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ]);

        $raw   = curl_exec($ch);
        $code  = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);

        if ($raw === false || $error !== '') {
            $this->verbose("  HTTP-01 fetch error: {$error}");
            return null;
        }

        if ($code < 200 || $code >= 300) {
            $this->verbose("  HTTP-01 non-2xx response: {$code}");
            return null;
        }

        return is_string($raw) ? $raw : null;
    }

    // -------------------------------------------------------------------------
    // Order Polling
    // -------------------------------------------------------------------------

    /** @param string[] $targetStatuses */
    private function pollOrderUntil(
        AcmeClient $client,
        JwsHelper  $jws,
        string     $kid,
        string     $orderUrl,
        array      $targetStatuses,
        array      &$state
    ): array {
        for ($i = 0; $i < self::MAX_ORDER_POLLS; $i++) {
            $order = $client->getOrderStatus($jws, $kid, $orderUrl);

            $this->verbose("Order poll {$i}: status={$order['status']}");

            if ($order['status'] === 'invalid') {
                return $order;
            }

            if (in_array($order['status'], $targetStatuses, true)) {
                $state['order_status'] = $order['status'];
                $this->state->saveOrderState($state['domain'], $state);
                return $order;
            }

            sleep(self::POLL_INTERVAL_SECS);
        }

        throw new \RuntimeException("Order did not reach " . implode('/', $targetStatuses) . " after " . (self::MAX_ORDER_POLLS * self::POLL_INTERVAL_SECS) . "s.");
    }

    // -------------------------------------------------------------------------
    // Error display
    // -------------------------------------------------------------------------

    private function displayOrderErrors(array $order): void
    {
        if (isset($order['error'])) {
            $this->err("  Error: " . ($order['error']['detail'] ?? json_encode($order['error'])));
        }
    }
}
