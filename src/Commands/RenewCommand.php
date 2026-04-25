<?php

declare(strict_types=1);

namespace Ubxty\UbxCert\Commands;

use Throwable;
use Ubxty\UbxCert\Acme\AcmeClient;
use Ubxty\UbxCert\Acme\JwsHelper;

/**
 * ubxcert renew
 *
 * Renews a single domain or all managed domains expiring within N days.
 * For automated Cloudflare-backed DNS-01 renewal, pass --cf-token and --cf-zone-id.
 *
 * Usage:
 *   ubxcert renew --domain example.com [--days-before 30] [--cf-token TOKEN] [--cf-zone-id ZONE]
 *   ubxcert renew --all [--days-before 30]
 */
class RenewCommand extends BaseCommand
{
    public function getName(): string        { return 'renew'; }
    public function getDescription(): string { return 'Renew expiring certificates'; }

    public function run(array $args): int
    {
        $this->parseCommonArgs($args);

        $domain      = $this->extractOption($args, 'domain');
        $all         = $this->hasFlag($args, 'all');
        $daysBefore  = (int) ($this->extractOption($args, 'days-before') ?? 30);
        $cfToken     = $this->extractOption($args, 'cf-token');
        $cfZoneId    = $this->extractOption($args, 'cf-zone-id');
        $webserver   = $this->extractOption($args, 'webserver') ?? 'nginx';

        if (!$domain && !$all) {
            $this->fail('Usage: ubxcert renew --domain example.com | --all [--days-before 30] [--webserver openresty|nginx|apache]');
            return 1;
        }

        $domains = $all ? $this->state->listCertDomains() : [$domain];

        if (empty($domains)) {
            $this->out('No managed certificates found.');
            return 0;
        }

        $renewed  = 0;
        $skipped  = 0;
        $failed   = 0;
        $errors   = [];

        foreach ($domains as $dom) {
            $expiry = $this->certs->getExpiryFormatted($dom);

            if (!$this->certs->needsRenewal($dom, $daysBefore)) {
                $this->out("  SKIP  {$dom} — {$expiry}");
                $skipped++;
                continue;
            }

            $this->out("  RENEW {$dom} — {$expiry}");

            try {
                $result = $this->renewDomain($dom, $cfToken, $cfZoneId, $webserver);
                if ($result) {
                    $renewed++;
                    $this->success("  Renewed {$dom}");
                } else {
                    $failed++;
                    $errors[] = $dom;
                }
            } catch (Throwable $e) {
                $failed++;
                $errors[] = "{$dom}: " . $e->getMessage();
                $this->fail("  Failed {$dom}: " . $e->getMessage());
            }
        }

        $this->out('');
        $this->out("Renewal complete: renewed={$renewed}, skipped={$skipped}, failed={$failed}");

        if (!empty($errors)) {
            foreach ($errors as $err) {
                $this->err("  ✗ {$err}");
            }
            return 1;
        }

        return 0;
    }

    // -------------------------------------------------------------------------
    // Domain renewal
    // -------------------------------------------------------------------------

    private function renewDomain(string $domain, ?string $cfToken, ?string $cfZoneId, string $webserver): bool
    {
        $state = $this->state->loadOrderState($domain);

        if (!$state) {
            $this->fail("  No order state for {$domain} — cannot renew. Run 'ubxcert request' manually.");
            return false;
        }

        $email   = $state['email'];
        $domains = $state['domains'];
        $staging = $state['staging'] ?? false;

        // Force a fresh order
        $this->state->deleteOrderState($domain);

        // --- Request new challenges -----------------------------------------
        $reqCmd = new RequestCommand();
        $reqArgs = ['--domains', implode(',', $domains), '--email', $email, '--force'];
        if ($staging) { $reqArgs[] = '--staging'; }
        if ($reqCmd->run($reqArgs) !== 0) {
            $this->fail("  Request step failed for {$domain}");
            return false;
        }

        $newState = $this->state->loadOrderState($domain);
        if (!$newState) {
            return false;
        }

        // --- Auto-set DNS via Cloudflare if credentials supplied -------------
        if ($cfToken && $cfZoneId) {
            foreach ($newState['challenges'] as $challenge) {
                $this->setCloudfareDnsTxt(
                    $cfToken,
                    $cfZoneId,
                    $challenge['challenge_host'],
                    $challenge['txt_value']
                );
            }
            // Wait briefly for Cloudflare to propagate
            sleep(30);
        }

        // --- Complete --------------------------------------------------------
        $complCmd = new CompleteCommand();
        $complArgs = ['--domain', $domain, '--wait-dns', '600'];
        if ($staging) { $complArgs[] = '--staging'; }
        if ($complCmd->run($complArgs) !== 0) {
            $this->fail("  Complete step failed for {$domain}");
            return false;
        }

        // --- Install --------------------------------------------------------
        $installCmd = new InstallWebserverCommand();
        $installArgs = ['--domain', $domain, '--webserver', $webserver];
        if ($installCmd->run($installArgs) !== 0) {
            $this->warn("  Install step failed for {$domain} (cert saved, web server not reloaded)");
        }

        return true;
    }

    // -------------------------------------------------------------------------
    // Cloudflare DNS helper for auto-renew
    // -------------------------------------------------------------------------

    private function setCloudfareDnsTxt(string $token, string $zoneId, string $name, string $value): void
    {
        $ch = curl_init("https://api.cloudflare.com/client/v4/zones/{$zoneId}/dns_records");
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => json_encode([
                'type'    => 'TXT',
                'name'    => $name,
                'content' => $value,
                'ttl'     => 60,
            ]),
            CURLOPT_HTTPHEADER => [
                "Authorization: Bearer {$token}",
                'Content-Type: application/json',
            ],
            CURLOPT_TIMEOUT        => 30,
            CURLOPT_SSL_VERIFYPEER => true,
        ]);

        $response = curl_exec($ch);
        $code     = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        curl_close($ch);

        if ($code !== 200) {
            $this->warn("  Cloudflare DNS TXT set returned HTTP {$code} for {$name}");
        } else {
            $this->verbose("  Cloudflare TXT set: {$name} = {$value}");
        }
    }
}
