<?php

declare(strict_types=1);

namespace Ubxty\UbxCert\Commands;

use Throwable;
use Ubxty\UbxCert\Acme\AcmeClient;
use Ubxty\UbxCert\Acme\JwsHelper;

/**
 * ubxcert complete
 *
 * Resumes a previously-created ACME order (from `ubxcert request`):
 *  1. Loads saved state from disk
 *  2. Optionally polls DNS until all TXT values are visible
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
 */
class CompleteCommand extends BaseCommand
{
    private const POLL_INTERVAL_SECS  = 5;
    private const MAX_ORDER_POLLS     = 60; // 5 min max
    private const DNS_POLL_INTERVAL   = 10;
    private const DNS_RESOLVERS       = ['8.8.8.8', '1.1.1.1', '8.8.4.4'];

    public function getName(): string        { return 'complete'; }
    public function getDescription(): string { return 'Complete ACME challenge, finalize order, download certificate'; }

    public function run(array $args): int
    {
        $this->parseCommonArgs($args);

        $domain  = $this->extractOption($args, 'domain');
        $waitDns = (int) ($this->extractOption($args, 'wait-dns') ?? 0);

        if (!$domain) {
            $this->fail('Usage: ubxcert complete --domain example.com [--wait-dns 600] [--staging] [--json]');
            return 1;
        }

        // --- Load order state -----------------------------------------------
        $state = $this->state->loadOrderState($domain);

        if (!$state) {
            $this->fail("No pending order found for '{$domain}'. Run 'ubxcert request' first.");
            return 1;
        }

        $this->out("Completing ACME order for: {$domain}");
        $this->out("Order status : {$state['order_status']}");

        // --- Reconstruct ACME client ----------------------------------------
        $staging    = $state['staging'] ?? $this->staging;
        $kid        = $state['kid'];
        $accountJws = JwsHelper::load($this->state->getAccountKeyPath($state['email']));
        $client     = new AcmeClient($staging);

        // --- Wait for DNS propagation (optional) ----------------------------
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
        $state['order_status']  = 'valid';
        $state['certificate_url'] = $certUrl;
        $state['completed_at']  = date('c');
        $this->state->saveOrderState($domain, $state);

        $expiry  = $this->certs->getExpiryFormatted($domain);
        $certDir = $this->state->getCertDir($domain);
        $this->log('info', "certificate issued for {$domain} expiry={$expiry}");

        if ($this->jsonMode) {
            $this->outputJson([
                'domain'       => $domain,
                'status'       => 'valid',
                'cert_dir'     => $certDir,
                'letsencrypt_live' => "/etc/letsencrypt/live/{$domain}",
                'fullchain_pem'=> "{$certDir}/fullchain.pem",
                'privkey_pem'  => "{$certDir}/privkey.pem",
                'expiry'       => $expiry,
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
