<?php

declare(strict_types=1);

namespace Ubxty\UbxCert\Commands;

/**
 * ubxcert list
 *
 * Lists all managed certificates with expiry status.
 *
 * Usage:
 *   ubxcert list [--json]
 */
class ListCommand extends BaseCommand
{
    public function getName(): string        { return 'list'; }
    public function getDescription(): string { return 'List all managed certificates'; }

    public function run(array $args): int
    {
        $this->parseCommonArgs($args);

        $domains = $this->state->listCertDomains();

        if (empty($domains)) {
            if ($this->jsonMode) {
                $this->outputJson(['certs' => []]);
            } else {
                $this->out('No managed certificates found.');
            }
            return 0;
        }

        $rows = [];
        foreach ($domains as $domain) {
            $expiry  = $this->certs->getCertExpiry($domain);
            $renewal = $this->certs->needsRenewal($domain);
            $order   = $this->state->loadOrderState($domain);
            $daysLeft = $expiry !== null ? (int)(($expiry - time()) / 86400) : null;

            $rows[] = [
                'domain'       => $domain,
                'status'       => $order['order_status'] ?? 'unknown',
                'expiry'       => $expiry !== null ? gmdate('Y-m-d', $expiry) . ' UTC' : 'N/A',
                'days_left'    => $daysLeft,
                'needs_renewal'=> $renewal,
                'cert_dir'     => $this->state->getCertDir($domain),
            ];
        }

        if ($this->jsonMode) {
            $this->outputJson(['certs' => $rows]);
            return 0;
        }

        $this->out(str_pad('DOMAIN', 40) . str_pad('STATUS', 12) . str_pad('EXPIRES', 25) . 'RENEWAL NEEDED');
        $this->out(str_repeat('-', 90));

        foreach ($rows as $row) {
            $need    = $row['needs_renewal'] ? "\033[31mYES\033[0m" : "\033[32mno\033[0m";
            $expires = $row['expiry'];
            if ($row['days_left'] !== null) {
                $expires .= " ({$row['days_left']}d)";
            }
            $this->out(
                str_pad($row['domain'], 40) .
                str_pad($row['status'], 12) .
                str_pad($expires, 25) .
                $need
            );
        }

        return 0;
    }
}
