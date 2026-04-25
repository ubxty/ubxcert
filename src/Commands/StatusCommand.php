<?php

declare(strict_types=1);

namespace Ubxty\UbxCert\Commands;

/**
 * ubxcert status
 *
 * Shows the current state of an in-progress or completed order,
 * including pending DNS challenge values.
 *
 * Usage:
 *   ubxcert status --domain example.com [--json]
 */
class StatusCommand extends BaseCommand
{
    public function getName(): string        { return 'status'; }
    public function getDescription(): string { return 'Show order / challenge status for a domain'; }

    public function run(array $args): int
    {
        $this->parseCommonArgs($args);

        $domain = $this->extractOption($args, 'domain');

        if (!$domain) {
            $this->fail('Usage: ubxcert status --domain example.com [--json]');
            return 1;
        }

        $state = $this->state->loadOrderState($domain);

        if (!$state) {
            if ($this->jsonMode) {
                $this->outputJson(['domain' => $domain, 'status' => 'no_order']);
            } else {
                $this->warn("No order found for '{$domain}'. Run 'ubxcert request' to start.");
            }
            return 0;
        }

        $expiry  = $this->certs->getExpiryFormatted($domain);
        $certDir = $this->state->getCertDir($domain);

        if ($this->jsonMode) {
            $this->outputJson([
                'domain'        => $domain,
                'domains'       => $state['domains'],
                'order_status'  => $state['order_status'],
                'staging'       => $state['staging'],
                'email'         => $state['email'],
                'created_at'    => $state['created_at'],
                'completed_at'  => $state['completed_at'],
                'cert_dir'      => $certDir,
                'cert_expiry'   => $expiry,
                'challenges'    => array_map(fn($c) => [
                    'domain'         => $c['domain'],
                    'challenge_host' => $c['challenge_host'],
                    'txt_value'      => $c['txt_value'],
                    'status'         => $c['status'],
                ], $state['challenges']),
            ]);
            return 0;
        }

        $this->out("Domain        : {$domain}");
        $this->out("Order status  : {$state['order_status']}");
        $this->out("Email         : {$state['email']}");
        $this->out("Staging       : " . ($state['staging'] ? 'yes' : 'no'));
        $this->out("Created       : {$state['created_at']}");
        $this->out("Completed     : " . ($state['completed_at'] ?? 'not yet'));
        $this->out("Certificate   : {$expiry}");

        if (!empty($state['challenges'])) {
            $this->out('');
            $this->out('DNS Challenges:');
            foreach ($state['challenges'] as $c) {
                $this->out("  [{$c['status']}] {$c['domain']}");
                $this->out("      Host  : {$c['challenge_host']}");
                $this->out("      Value : {$c['txt_value']}");
            }
        }

        return 0;
    }
}
