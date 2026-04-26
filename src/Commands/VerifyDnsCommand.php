<?php

declare(strict_types=1);

namespace Ubxty\UbxCert\Commands;

/**
 * ubxcert verify-dns
 *
 * Quick read-only DNS check for the saved order's TXT challenge values.
 *
 * Unlike `complete`, this command never contacts the ACME server and never
 * mutates any state — it only queries authoritative DNS resolvers and
 * reports which expected TXT values are visible. Useful as a cheap
 * pre-flight before `complete` (avoids burning a finalize attempt when DNS
 * has not yet propagated).
 *
 * Usage:
 *   ubxcert verify-dns --domain example.com
 *   ubxcert verify-dns --domain example.com --json
 *   ubxcert verify-dns --domain example.com --resolver 8.8.8.8 --resolver 1.1.1.1
 */
class VerifyDnsCommand extends BaseCommand
{
    /** @var string[] */
    private const DEFAULT_RESOLVERS = ['8.8.8.8', '1.1.1.1', '8.8.4.4'];

    public function getName(): string        { return 'verify-dns'; }
    public function getDescription(): string { return 'Check DNS-01 TXT records without contacting ACME or mutating state'; }

    public function run(array $args): int
    {
        $this->parseCommonArgs($args);

        $domain    = $this->extractOption($args, 'domain');
        $resolvers = $this->extractMulti($args, 'resolver');
        if (empty($resolvers)) {
            $resolvers = self::DEFAULT_RESOLVERS;
        }

        if (!$domain) {
            $this->fail('Usage: ubxcert verify-dns --domain example.com [--resolver 8.8.8.8] [--json]');
            return 1;
        }

        $state = $this->state->loadOrderState($domain);
        if (!$state) {
            if ($this->jsonMode) {
                $this->outputJson([
                    'domain' => $domain,
                    'status' => 'no_order',
                    'message' => "No order state on disk for {$domain}. Run 'ubxcert request' first.",
                ]);
            } else {
                $this->warn("No order state on disk for '{$domain}'. Run 'ubxcert request' first.");
            }
            return 1;
        }

        $challenges = $state['challenges'] ?? [];
        if (empty($challenges)) {
            $this->fail("Order state has no DNS-01 challenges.");
            return 1;
        }

        $results = [];
        $allOk   = true;

        foreach ($challenges as $challenge) {
            $host  = $challenge['challenge_host'] ?? null;
            $want  = $challenge['txt_value'] ?? null;
            if (!$host || !$want) {
                continue;
            }

            $found    = $this->resolveTxt($host, $resolvers);
            $matched  = in_array($want, $found, true);
            $allOk    = $allOk && $matched;
            $results[] = [
                'domain'         => $challenge['domain'] ?? null,
                'challenge_host' => $host,
                'expected'       => $want,
                'found'          => $found,
                'matched'        => $matched,
            ];
        }

        if ($this->jsonMode) {
            $this->outputJson([
                'domain'    => $domain,
                'all_ok'    => $allOk,
                'resolvers' => $resolvers,
                'records'   => $results,
                'next_step' => $allOk
                    ? "ubxcert complete --domain {$domain}" . (($state['staging'] ?? false) ? ' --staging' : '')
                    : 'Wait for DNS to propagate, then re-run verify-dns.',
            ]);
            return $allOk ? 0 : 2;
        }

        foreach ($results as $r) {
            if ($r['matched']) {
                $this->success("TXT {$r['challenge_host']} → matched");
            } else {
                $this->warn("TXT {$r['challenge_host']} → expected '{$r['expected']}', found: " . (empty($r['found']) ? 'none' : implode(', ', $r['found'])));
            }
        }

        if ($allOk) {
            $this->out('');
            $this->success("All DNS-01 TXT records visible. Run:");
            $this->out("  ubxcert complete --domain {$domain}" . (($state['staging'] ?? false) ? ' --staging' : ''));
            return 0;
        }

        $this->out('');
        $this->warn('DNS not fully propagated yet. Re-run this command in a minute.');
        return 2;
    }

    /**
     * Extract every occurrence of a repeatable option (e.g. --resolver 1.1.1.1 --resolver 8.8.8.8).
     *
     * @return string[]
     */
    private function extractMulti(array &$args, string $name): array
    {
        $values = [];
        while (($v = $this->extractOption($args, $name)) !== null) {
            $values[] = $v;
        }
        return $values;
    }

    /**
     * Query each resolver for TXT and return the union of values found.
     *
     * @param string[] $resolvers
     * @return string[]
     */
    private function resolveTxt(string $host, array $resolvers): array
    {
        $values = [];
        foreach ($resolvers as $resolver) {
            $output = @shell_exec('dig +short TXT ' . escapeshellarg($host) . ' @' . escapeshellarg($resolver) . ' 2>/dev/null');
            if (!$output) {
                continue;
            }
            foreach (preg_split('/\R/', trim($output)) as $line) {
                $line = trim($line, " \t\"");
                if ($line !== '' && !in_array($line, $values, true)) {
                    $values[] = $line;
                }
            }
        }
        return $values;
    }
}
