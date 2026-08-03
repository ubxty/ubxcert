<?php

declare(strict_types=1);

namespace Ubxty\UbxCert\Commands;

use Throwable;
use Ubxty\UbxCert\Acme\AcmeClient;
use Ubxty\UbxCert\Util\WebrootChallenger;

/**
 * ubxcert request
 *
 * Creates a new ACME order, computes the chosen challenge values
 * (DNS-01 or HTTP-01), and persists full order state to disk so
 * `ubxcert complete` can resume it.
 *
 * Defaults (v1.2.0+):
 *   - --challenge defaults to 'http' when the domain list contains no
 *     wildcard, otherwise 'dns'. Override with --challenge dns|http.
 *   - For HTTP-01 single domains, the auto-chain runs by default:
 *     request → complete → install in one shot. Pass --no-auto to
 *     preview challenge values and finish manually.
 *   - DNS-01 / wildcards always print the TXT records and stop the
 *     chain at request (no DNS provider integration in scope).
 *
 * Usage:
 *   # Default — one-shot issue + install for a single domain
 *   ubxcert request --domains "example.com" --email admin@example.com
 *
 *   # Wildcard — DNS-01 (HTTP-01 cannot serve *.); prints TXT records
 *   ubxcert request --domains "*.example.com,example.com" --email admin@example.com
 *
 *   # Manual / preview — disable the auto-chain
 *   ubxcert request --domains "example.com" --email admin@example.com --no-auto
 *
 *   # Other flags:
 *   ubxcert request --domains "*.example.com,example.com" --email admin@example.com --json
 *   ubxcert request --domains "*.example.com,example.com" --email admin@example.com --staging --force
 */
class RequestCommand extends BaseCommand
{
    private const CHALLENGE_DNS  = 'dns';
    private const CHALLENGE_HTTP = 'http';

    /** Default --wait-http seconds when --auto is set on HTTP-01. */
    private const AUTO_DEFAULT_WAIT_HTTP = 120;

    /** Default --wait-dns seconds when --auto is set on DNS-01 (used as a hint). */
    private const AUTO_DEFAULT_WAIT_DNS  = 600;

    public function getName(): string        { return 'request'; }
    public function getDescription(): string { return 'Create ACME order and output challenge info (DNS-01 or HTTP-01)'; }

    public function run(array $args): int
    {
        $this->parseCommonArgs($args);

        $domainsRaw        = $this->extractOption($args, 'domains');
        $email             = $this->extractOption($args, 'email');
        $force             = $this->hasFlag($args, 'force');
        $noAuto            = $this->hasFlag($args, 'no-auto');
        $auto              = !$noAuto; // ON by default for HTTP-01 (v1.2.0+); --no-auto opts out
        $waitHttpOpt       = $this->extractOption($args, 'wait-http');
        $waitDnsOpt        = $this->extractOption($args, 'wait-dns');
        $installWebserver  = $this->extractOption($args, 'install-webserver');
        $challengeOverride = $this->extractOption($args, 'challenge');
        $renew             = $this->hasFlag($args, 'renew');
        $quietEvents       = $this->hasFlag($args, 'quiet-events');
        $precheck          = $this->hasFlag($args, 'precheck');

        if (!$domainsRaw || !$email) {
            $this->emitErrorJson('usage', 'Usage: ubxcert request --domains "*.example.com,example.com" --email admin@example.com [--challenge dns|http] [--no-auto] [--staging] [--force] [--renew] [--precheck] [--json]');
            return 1;
        }

        // Build the domain list first so we can auto-detect a sensible
        // --challenge default before validating wildcard-vs-HTTP-01.
        $domains    = array_map('trim', explode(',', $domainsRaw));
        $domains    = array_values(array_filter($domains, fn($d) => $d !== ''));
        $baseDomain = $this->extractBaseDomain($domains);

        // Resolve challenge: explicit override > auto-detect > dns (legacy default).
        $challenge = $challengeOverride !== null
            ? strtolower($challengeOverride)
            : $this->detectChallenge($domains);

        if (!in_array($challenge, [self::CHALLENGE_DNS, self::CHALLENGE_HTTP], true)) {
            $this->emitErrorJson('invalid_challenge', "Invalid --challenge value '{$challenge}'. Use 'dns' or 'http'.");
            return 1;
        }

        // HTTP-01 cannot satisfy wildcard identifiers — RFC 8555 §7.2.
        if ($challenge === self::CHALLENGE_HTTP) {
            foreach ($domains as $d) {
                if (str_starts_with($d, '*.')) {
                    $this->emitErrorJson('http01_wildcard_unsupported', "HTTP-01 does not support wildcards. Found: {$d}. Use --challenge dns (default for wildcards) or omit --challenge.");
                    return 1;
                }
            }
        }

        // Surface useless arg combinations early (still harmless if --auto is off,
        // but the user is asking for semantics that don't apply to the chosen path).
        if ($challenge === self::CHALLENGE_DNS && $waitHttpOpt !== null) {
            $this->emitErrorJson('incompatible_flags', '--wait-http is not compatible with --challenge dns. Use --wait-dns for wildcard/DNS-01.');
            return 1;
        }

        $challengeLabel = $challenge === self::CHALLENGE_HTTP ? 'HTTP-01' : 'DNS-01';
        $this->out("Requesting ACME {$challengeLabel} challenge for: " . implode(', ', $domains));
        $this->out($this->staging ? '[STAGING mode]' : '[PRODUCTION Let\'s Encrypt]');

        // --- Check for existing valid order (unless --force) ----------------
        if (!$force) {
            $existing = $this->state->loadOrderState($baseDomain);
            if ($existing && in_array($existing['order_status'] ?? '', ['pending', 'ready'], true)) {
                // Only re-print the existing order if its challenge type matches
                // the one the user asked for. Otherwise --force is required.
                $existingType = $existing['challenge_type'] ?? self::CHALLENGE_DNS;
                if ($existingType !== $challenge) {
                    $this->emitErrorJson('existing_order_mismatch', "Existing pending order uses '{$existingType}' challenge. Use --force to recreate with '{$challenge}'.");
                    return 1;
                }
                $this->out("Existing pending order found. Use --force to create a new one.");
                return $this->outputChallenges($existing);
            }
        }

        // --- --renew: skip the new ACME order, run complete → install on the
        // existing cert subject. Cheaper than --force, no rate-limit exposure.
        if ($renew) {
            $certDir = $this->state->getCertDir($baseDomain);
            if (!file_exists($certDir . '/fullchain.pem')) {
                $this->emitErrorJson('no_existing_cert', "No existing certificate for {$baseDomain}. Run 'ubxcert request' (without --renew) first.");
                return 1;
            }
            return $this->renewExisting($baseDomain, $domains, $challenge, $waitHttpOpt, $waitDnsOpt, $installWebserver, $quietEvents);
        }

        // --- --precheck: dry-run validation. Emits JSON with checks[].
        if ($precheck) {
            return $this->runPrecheck($baseDomain, $domains, $challenge, $email);
        }

        // --- Resolve ACME account -------------------------------------------
        try {
            [$jws, $kid, $client] = $this->resolveAccount($email);
        } catch (Throwable $e) {
            $this->log('error', 'account setup failed: ' . $e->getMessage());
            $this->emitErrorJson('account_setup_failed', 'Account setup failed: ' . $e->getMessage());
            return 1;
        }

        // --- Create order ----------------------------------------------------
        try {
            $this->verbose('Creating ACME order...');
            $order = $client->newOrder($jws, $kid, $domains);
            $this->verbose("Order URL: {$order['order_url']}");
        } catch (Throwable $e) {
            $this->log('error', 'new order failed: ' . $e->getMessage());
            $this->emitErrorJson('new_order_failed', 'New order failed: ' . $e->getMessage());
            return 1;
        }

        // --- Fetch authorizations and compute challenge values --------------
        $challenges = [];
        $type       = $challenge === self::CHALLENGE_HTTP ? 'http-01' : 'dns-01';
        $authErrors = [];

        foreach ($order['authorizations'] as $authzUrl) {
            try {
                $authz   = $client->getAuthorization($jws, $kid, $authzUrl);
                $domain  = $authz['identifier']['value'];
                $picked  = null;

                foreach ($authz['challenges'] ?? [] as $chall) {
                    if (($chall['type'] ?? null) === $type) {
                        $picked = $chall;
                        break;
                    }
                }

                if ($picked === null) {
                    $available = array_map(
                        fn($c) => $c['type'] ?? 'unknown',
                        $authz['challenges'] ?? []
                    );
                    $msg = "No {$type} challenge offered for domain: {$domain}. Available: " . (empty($available) ? 'none' : implode(', ', $available));
                    $this->log('error', $msg);
                    $authErrors[] = [
                        'domain'       => $domain,
                        'authz_url'    => $authzUrl,
                        'error_code'   => 'no_challenge_offered',
                        'requested'    => $type,
                        'available'    => $available,
                    ];
                    // Don't bail immediately — let the loop continue so all
                    // authz errors are surfaced in the JSON payload.
                    continue;
                }

                $challenges[] = $this->buildChallengeRecord(
                    $challenge,
                    $domain,
                    $authz['status'] ?? 'pending',
                    $authzUrl,
                    $picked,
                    $jws
                );

                $this->verbose("Challenge for {$domain}: type={$type}");
            } catch (Throwable $e) {
                $this->log('error', 'authorization fetch failed: ' . $e->getMessage());
                $this->emitErrorJson('authorization_fetch_failed', 'Authorization fetch failed: ' . $e->getMessage(), [
                    'partial_challenges' => $challenges,
                    'auth_errors'        => $authErrors,
                ]);
                return 1;
            }
        }

        // If we collected zero challenges, every domain either errored or
        // had no compatible challenge type. Emit a structured failure so the
        // panel can distinguish "ACME offered nothing" from "no order at all".
        if (empty($challenges)) {
            $this->emitErrorJson('no_challenge_offered', 'No compatible ACME challenge could be obtained for any domain.', [
                'auth_errors' => $authErrors,
                'attempted'   => $type,
            ]);
            return 1;
        }

        // --- Generate the certificate private key and save state ------------
        try {
            $this->certs->generateCertKey($baseDomain);
        } catch (Throwable $e) {
            $this->log('error', 'certificate key generation failed: ' . $e->getMessage());
            $this->emitErrorJson('cert_key_generation_failed', 'Certificate key generation failed: ' . $e->getMessage());
            return 1;
        }

        $state = [
            'domain'          => $baseDomain,
            'domains'         => $domains,
            'email'           => $email,
            'staging'         => $this->staging,
            'challenge_type'  => $challenge,                 // 'dns' | 'http'
            'account_dir'     => $this->state->getAccountDir($email),
            'kid'             => $kid,
            'order_url'       => $order['order_url'],
            'finalize_url'    => $order['finalize'],
            'certificate_url' => null,
            'cert_key_path'   => $this->state->getOrderCertKeyPath($baseDomain),
            'challenges'      => $challenges,
            'order_status'    => $order['status'],
            'created_at'      => date('c'),
            'completed_at'    => null,
        ];

        $this->state->saveOrderState($baseDomain, $state);
        $this->log('info', "order created for {$baseDomain} domains=[" . implode(',', $domains) . "] challenge={$challenge} staging=" . ($this->staging ? 'yes' : 'no'));
        $this->verbose("Order state saved to: " . $this->state->getOrderDir($baseDomain) . '/state.json');

        // --- Auto-webroot (HTTP-01 only, default ON) -----------------------
        $autoWebroot    = $challenge === self::CHALLENGE_HTTP && !$this->hasFlag($args, 'no-auto-webroot');
        $explicitRoot   = $this->extractOption($args, 'webroot');
        $autoWebrootResults = [];
        if ($autoWebroot) {
            $autoWebrootResults = $this->runAutoWebroot($state, $explicitRoot);
            $state['auto_webroot'] = $autoWebrootResults;
        }

        // --- Optional auto-chain: request → complete → install -----------
        if ($auto) {
            return $this->runAutoChain(
                $baseDomain,
                $domains,
                $challenge,
                $waitHttpOpt,
                $waitDnsOpt,
                $installWebserver,
                $this->staging,
                $this->jsonMode,
                $this->verbose,
                $state
            );
        }

        return $this->outputChallenges($state);
    }

    /**
     * For each HTTP-01 challenge, attempt to write the challenge file
     * to the auto-detected docroot and verify reachability. Never
     * throws — a failure here is a warning, not an error, because the
     * operator may have explicitly chosen manual serve or may be
     * running from a location where auto-detection is impossible.
     *
     * @return array<int, array<string, mixed>>
     */
    private function runAutoWebroot(array $state, ?string $explicitRoot): array
    {
        $results = [];
        $seen    = [];
        foreach ($state['challenges'] ?? [] as $c) {
            $token = $c['token'] ?? null;
            $domain = $c['domain'] ?? null;
            if (!$token || !$domain) {
                continue;
            }
            // One challenge per domain — skip duplicates by token.
            if (isset($seen[$token])) {
                continue;
            }
            $seen[$token] = true;

            $result = WebrootChallenger::write(
                $domain,
                $token,
                $c['key_authorization'] ?? '',
                $explicitRoot,
                true
            );
            $results[] = $result;

            $this->out('');
            if ($result['wrote'] && $result['verified']) {
                $this->success("HTTP-01 auto-served: {$result['file_path']} (verified at {$result['url']})");
            } elseif ($result['wrote']) {
                $this->out("\033[33mHTTP-01 file written but not yet reachable from outside: {$result['file_path']}\033[0m");
                if (!empty($result['error'])) {
                    $this->out("\033[33m  " . $result['error'] . "\033[0m");
                }
            } else {
                $this->out("\033[33mHTTP-01 auto-webroot skipped for {$domain}: " . ($result['error'] ?? 'unknown reason') . "\033[0m");
                if ($explicitRoot === null) {
                    $this->out("\033[2m  Pass --webroot=/path or --no-auto-webroot to take manual control.\033[0m");
                }
            }
        }
        return $results;
    }

    // -------------------------------------------------------------------------
    // --renew: skip the ACME order, re-run complete→install on the existing cert
    // -------------------------------------------------------------------------

    /**
     * Re-issue and re-install the existing certificate without contacting
     * the ACME server for a new order. The new cert keeps the same domain
     * subject, so no DNS-01 or HTTP-01 challenges are required.
     *
     * Implementation: build a synthetic state from the existing fullchain.pem
     * + the previously-saved order state, then run the same auto-chain
     * logic that `request --auto` would use.
     */
    private function renewExisting(
        string $baseDomain,
        array $domains,
        string $challenge,
        ?string $waitHttpOpt,
        ?string $waitDnsOpt,
        ?string $installWebserver,
        bool $quietEvents
    ): int {
        $this->out("Renewing existing certificate for {$baseDomain} (no new ACME order).");

        $state = $this->state->loadOrderState($baseDomain) ?? [
            'domain'          => $baseDomain,
            'domains'         => $domains,
            'email'           => null,
            'staging'         => $this->staging,
            'challenge_type'  => $challenge,
            'order_status'    => 'valid',
            'created_at'      => date('c'),
            'completed_at'    => date('c'),
            'challenges'      => [],
        ];

        // In --renew mode we skip the ACME round-trip entirely. Always force
        // the auto-chain (`complete` becomes a no-op since the cert is already
        // on disk; `install` re-wires the vhost).
        return $this->runAutoChain(
            $baseDomain,
            $domains,
            $challenge,
            $waitHttpOpt,
            $waitDnsOpt,
            $installWebserver,
            $this->staging,
            $this->jsonMode,
            $this->verbose || !$quietEvents,
            $state
        );
    }

    // -------------------------------------------------------------------------
    // --precheck: dry-run validation
    // -------------------------------------------------------------------------

    /**
     * Run a battery of checks without issuing an ACME order. Emits JSON
     * with `{status, checks: [{name, ok, message, ...}]}` so the panel
     * can render a "Will this work?" wizard before the user commits.
     */
    private function runPrecheck(string $baseDomain, array $domains, string $challenge, string $email): int
    {
        $checks = [];

        // --- 1. ACME account exists or can be created ------------------------
        $checks[] = $this->precheckAccount($email);

        // --- 2. Webserver detection -------------------------------------------
        $checks[] = $this->precheckWebserver();

        // --- 3. Docroot writability (HTTP-01 only) ---------------------------
        if ($challenge === self::CHALLENGE_HTTP) {
            $checks[] = $this->precheckDocroot($baseDomain);
        }

        // --- 4. DNS resolution for the domain (HTTP-01) -----------------------
        $checks[] = $this->precheckDns($baseDomain);

        // --- 5. PHP extensions -----------------------------------------------
        $checks[] = $this->precheckExtensions();

        // --- 6. Existing cert optional (informational) -----------------------
        $checks[] = $this->precheckExistingCert($baseDomain);

        // --- 7. Reachability of http://domain from local interface -----------
        if ($challenge === self::CHALLENGE_HTTP) {
            $checks[] = $this->precheckLocalReachability($baseDomain);
        }

        $allOk = !in_array(false, array_map(fn($c) => $c['ok'], $checks), true);

        $payload = [
            'status'        => $allOk ? 'ready' : 'precheck-failed',
            'domain'        => $baseDomain,
            'domains'       => $domains,
            'challenge'     => $challenge,
            'checks'        => $checks,
            'precheck_ok'   => $allOk,
        ];

        if ($this->jsonMode) {
            $this->outputJson($payload);
        } else {
            $this->out('');
            $this->out($allOk ? "\033[32m✓ Precheck passed.\033[0m" : "\033[31m✗ Precheck failed.\033[0m");
            foreach ($checks as $c) {
                $icon = $c['ok'] ? "\033[32m✓\033[0m" : "\033[31m✗\033[0m";
                $this->out("  {$icon} {$c['name']}: {$c['message']}");
            }
            $this->out('');
        }

        return $allOk ? 0 : 1;
    }

    /** @return array<string, mixed> */
    private function precheckAccount(string $email): array
    {
        $exists = $this->state->accountExists($email);
        return [
            'name'    => 'acme_account',
            'ok'      => true,
            'message' => $exists
                ? "Account already registered for {$email}"
                : "Account will be registered on next request ({$email})",
            'will_register' => !$exists,
        ];
    }

    /** @return array<string, mixed> */
    private function precheckWebserver(): array
    {
        $primary = \Ubxty\UbxCert\Util\VhostScanner::detectPrimary();
        if ($primary === null) {
            return [
                'name' => 'webserver',
                'ok'   => false,
                'message' => 'No active web server detected. Pass --install-webserver=openresty|nginx|apache to override.',
                'error_code' => 'no_webserver_detected',
            ];
        }
        return [
            'name'    => 'webserver',
            'ok'      => true,
            'message' => "Active web server: {$primary}",
            'webserver' => $primary,
        ];
    }

    /** @return array<string, mixed> */
    private function precheckDocroot(string $domain): array
    {
        $info = \Ubxty\UbxCert\Util\VhostScanner::resolveDocroot($domain);
        if ($info === null) {
            return [
                'name' => 'docroot',
                'ok'   => false,
                'message' => "No document root detected for {$domain}. Pass --webroot=/path to override.",
                'error_code' => 'no_docroot',
            ];
        }
        if (!is_writable($info['docroot'])) {
            return [
                'name' => 'docroot',
                'ok'   => false,
                'message' => "Document root not writable: {$info['docroot']}",
                'docroot' => $info['docroot'],
                'error_code' => 'docroot_not_writable',
            ];
        }
        return [
            'name'    => 'docroot',
            'ok'      => true,
            'message' => "Document root: {$info['docroot']} (writable)",
            'docroot' => $info['docroot'],
            'webserver' => $info['webserver'] ?? null,
        ];
    }

    /** @return array<string, mixed> */
    private function precheckDns(string $domain): array
    {
        $ip = @gethostbyname($domain);
        if ($ip === $domain) {
            return [
                'name' => 'dns',
                'ok'   => false,
                'message' => "DNS resolution failed for {$domain}",
                'error_code' => 'dns_resolution_failed',
            ];
        }
        return [
            'name' => 'dns',
            'ok'   => true,
            'message' => "{$domain} -> {$ip}",
            'ip'   => $ip,
        ];
    }

    /** @return array<string, mixed> */
    private function precheckExtensions(): array
    {
        $missing = [];
        foreach (['openssl', 'json', 'curl'] as $ext) {
            if (!extension_loaded($ext)) {
                $missing[] = $ext;
            }
        }
        if (!empty($missing)) {
            return [
                'name' => 'php_extensions',
                'ok'   => false,
                'message' => 'Missing PHP extensions: ' . implode(', ', $missing),
                'missing' => $missing,
                'error_code' => 'missing_php_extensions',
            ];
        }
        return [
            'name'    => 'php_extensions',
            'ok'      => true,
            'message' => 'All required PHP extensions loaded',
        ];
    }

    /** @return array<string, mixed> */
    private function precheckExistingCert(string $domain): array
    {
        $certDir = $this->state->getCertDir($domain);
        $exists  = file_exists($certDir . '/fullchain.pem');
        if (!$exists) {
            return [
                'name'    => 'existing_cert',
                'ok'      => true,
                'message' => "No existing certificate for {$domain} (fresh issuance)",
                'exists'  => false,
            ];
        }
        $expiry = $this->certs->getCertExpiry($domain);
        $daysLeft = $expiry !== null ? (int)(($expiry - time()) / 86400) : null;
        return [
            'name'    => 'existing_cert',
            'ok'      => true,
            'message' => $daysLeft !== null
                ? "Existing cert expires in {$daysLeft} days"
                : "Existing cert present (expiry unknown)",
            'exists'  => true,
            'days_left' => $daysLeft,
        ];
    }

    /** @return array<string, mixed> */
    private function precheckLocalReachability(string $domain): array
    {
        $ctx = stream_context_create(['http' => ['timeout' => 5, 'ignore_errors' => true]]);
        $body = @file_get_contents("http://{$domain}/.well-known/acme-challenge/ubxcert-precheck", false, $ctx);
        $status = isset($http_response_header[0]) ? $http_response_header[0] : '';
        if ($body === false && $status === '') {
            return [
                'name' => 'local_reachability',
                'ok'   => false,
                'message' => "Could not reach http://{$domain}/ from local interface. "
                    . "If the domain is behind a CDN, ensure port 80 is reachable on the origin.",
                'error_code' => 'local_unreachable',
            ];
        }
        return [
            'name'    => 'local_reachability',
            'ok'      => true,
            'message' => "Reachable: {$status}",
            'response' => $status,
        ];
    }

    // -------------------------------------------------------------------------
    // Default-challenge detection + auto-chain
    // -------------------------------------------------------------------------

    /**
     * Pick a default --challenge value based on the domain list.
     *
     * - Any wildcard identifier (`*.foo`) forces DNS-01 (HTTP-01 cannot
     *   satisfy wildcards per RFC 8555 §7.2).
     * - Otherwise default to HTTP-01 — it's dramatically faster (no DNS
     *   propagation wait) and ubxcert auto-serves the challenge file.
     */
    private function detectChallenge(array $domains): string
    {
        foreach ($domains as $d) {
            if (is_string($d) && str_starts_with($d, '*.')) {
                return self::CHALLENGE_DNS;
            }
        }
        return self::CHALLENGE_HTTP;
    }

    /**
     * Drive `complete → install` after a successful `request` when --auto
     * was passed. Returns the final exit code of the chain.
     *
     * Behaviour:
     *  - HTTP-01 single-domain case: chains `complete --wait-http N` then
     *    `install` into the detected web server (or --install-webserver
     *    override), printing banner lines along the way.
     *  - DNS-01 / wildcard case: prints a single yellow note explaining the
     *    manual TXT-record requirement, then exits 0. No DNS provider
     *    integration is in scope for v1.2.0.
     *  - On any failure: cert files at /etc/ubxcert/certs/<domain>/ are
     *    still on disk; the failure is reported with the suggested re-run
     *    command and the appropriate exit code is propagated.
     *
     * @return int The chain's final exit code (0 = full success).
     */
    private function runAutoChain(
        string $baseDomain,
        array  $domains,
        string $challenge,
        ?string $waitHttpOpt,
        ?string $waitDnsOpt,
        ?string $installWebserver,
        bool   $staging,
        bool   $jsonMode,
        bool   $verbose,
        array  $state
    ): int {
        $isHttp = $challenge === self::CHALLENGE_HTTP;

        // Resolve effective wait times. Honour the explicit flag, then
        // the env var, then the default constant.
        $envWaitHttp = getenv('UBXCERT_AUTO_WAIT_HTTP');
        $envWaitDns  = getenv('UBXCERT_AUTO_WAIT_DNS');
        $waitHttp    = $waitHttpOpt !== null
            ? (int) $waitHttpOpt
            : ($envWaitHttp !== false && $envWaitHttp !== '' ? (int) $envWaitHttp : self::AUTO_DEFAULT_WAIT_HTTP);
        $waitDns     = $waitDnsOpt !== null
            ? (int) $waitDnsOpt
            : ($envWaitDns !== false && $envWaitDns !== '' ? (int) $envWaitDns : self::AUTO_DEFAULT_WAIT_DNS);

        $chainResult = [
            'request'       => ['domain' => $baseDomain, 'challenge_type' => $challenge, 'domains' => $domains, 'auto' => true],
            'complete'      => null,
            'install'       => null,
        ];

        // --- DNS-01 / wildcard case: chain stops here -----------------------
        // The cert order is created, but issue/download/install must wait
        // for the operator to add the DNS TXT records. No DNS provider
        // integration in v1.2.0 — this is a deliberate scope limit.
        if (!$isHttp) {
            $this->warn('Wildcard / DNS-01 requires manual TXT records. Auto-chain stops at request.');
            $stagingFlag = $staging ? ' --staging' : '';
            $this->out('');
            $this->out('After adding the TXT records printed above, run:');
            $this->out("  ubxcert complete --domain {$baseDomain} --wait-dns {$waitDns}{$stagingFlag}");
            $this->out('Or to opt out of the auto-chain entirely (preview challenges only): add --no-auto.');
            $this->out('');

            if ($jsonMode) {
                $payload = $this->buildChallengeOutput($state) + $chainResult;
                $payload['auto_chain'] = $chainResult;
                $payload['domain']     = $baseDomain;
                $payload['status']     = 'awaiting-challenge';
                $payload['next_step']  = "ubxcert complete --domain {$baseDomain} --wait-dns {$waitDns}" . ($state['staging'] ? ' --staging' : '');
                $this->outputJson($payload);
            }
            return 0;
        }

        // --- Step 2: complete (HTTP-01) -------------------------------------
        if (!$jsonMode) {
            $this->out('');
            $this->out('--- Auto-chain: complete ---');
        }

        $complete = new CompleteCommand();
        $completeArgs = ['--domain', $baseDomain, '--challenge', 'http', '--wait-http', (string) $waitHttp];
        if ($staging)  { $completeArgs[] = '--staging'; }
        if ($verbose)  { $completeArgs[] = '--verbose'; }
        // NOTE: never pass --json to the inner command. In auto-chain mode
        // this command emits a single envelope at the end of runAutoChain;
        // a second JSON document from the sub-command would corrupt the
        // panel's `json.load` of the captured stdout. The sub-command's
        // stdout is captured below so operators still see it in the
        // envelope's `chainResult[*].output` field.

        $buffered = '';
        ob_start();
        $code = $complete->run($completeArgs);
        $buffered = (string) ob_get_clean();
        $chainResult['complete'] = ['exit' => $code, 'wait_http' => $waitHttp];
        if ($jsonMode && $buffered !== '') {
            $chainResult['complete']['output'] = trim($buffered);
        }

        if ($code !== 0) {
            $chainResult['install'] = ['skipped' => true, 'reason' => 'complete-failed'];
            if (!$jsonMode) {
                $this->fail("Auto-chain stopped at 'complete' (exit {$code}). Cert files may be partially saved at /etc/ubxcert/certs/{$baseDomain}/. Re-run:");
                $this->out("  ubxcert complete --domain {$baseDomain} --challenge http --wait-http {$waitHttp}" . ($staging ? ' --staging' : ''));
                $this->out("  ubxcert install  --domain {$baseDomain} --webserver openresty|nginx|apache");
            }
            if ($jsonMode) {
                $payload = $this->buildChallengeOutput($state) + $chainResult;
                $payload['auto_chain'] = $chainResult;
                $payload['domain']     = $baseDomain;
                $payload['status']     = 'auto-chain-failed';
                $payload['error_code'] = 'complete_failed';
                $payload['error']      = "Auto-chain stopped at 'complete' (exit {$code}).";
                $this->outputJson($payload);
            }
            return $code;
        }

        // --- Step 3: install (auto-pick webserver) --------------------------
        // Priority: --install-webserver > vhost-deduced webserver > running primary.
        $ws = $installWebserver;
        $docrootInfo = \Ubxty\UbxCert\Util\VhostScanner::resolveDocroot($baseDomain);
        if ($ws === null && $docrootInfo !== null && isset($docrootInfo['webserver'])) {
            $ws = $docrootInfo['webserver'];
        }
        if ($ws === null) {
            $ws = \Ubxty\UbxCert\Util\VhostScanner::detectPrimary();
        }

        if ($ws === null) {
            $chainResult['install'] = ['skipped' => true, 'reason' => 'no-webserver-detected'];
            if (!$jsonMode) {
                $this->warn("Cert issued and saved for {$baseDomain}, but no active web server was detected.");
                $this->out('Install manually with:');
                $this->out("  ubxcert install --domain {$baseDomain} --webserver openresty|nginx|apache");
            }
            if ($jsonMode) {
                $payload = $this->buildChallengeOutput($state) + $chainResult;
                $payload['auto_chain'] = $chainResult;
                $payload['domain']     = $baseDomain;
                $payload['status']     = 'auto-chain-partial';
                $payload['error_code'] = 'no_webserver_detected';
                $payload['error']      = "Cert issued and saved for {$baseDomain}, but no active web server was detected.";
                $this->outputJson($payload);
            }
            return 0;
        }

        if (!$jsonMode) {
            $this->out('');
            $this->out('--- Auto-chain: install ---');
            $this->out("  webserver : {$ws}");
        }

        $installer    = new InstallWebserverCommand();
        $installArgs  = ['--domain', $baseDomain, '--webserver', $ws];
        if ($verbose)  { $installArgs[] = '--verbose'; }
        // Same rationale as the CompleteCommand call above: keep the auto-
        // chain's stdout as a single JSON document; capture sub-command
        // output into the envelope so the operator can still inspect it.

        $buffered = '';
        ob_start();
        $code = $installer->run($installArgs);
        $buffered = (string) ob_get_clean();
        $chainResult['install'] = [
            'exit'         => $code,
            'webserver'    => $ws,
            'docroot_info' => $docrootInfo !== null
                ? [
                    'docroot'     => $docrootInfo['docroot']     ?? null,
                    'webserver'   => $docrootInfo['webserver']   ?? null,
                    'config_path' => $docrootInfo['config_path'] ?? null,
                ]
                : null,
        ];
        if ($jsonMode && $buffered !== '') {
            $chainResult['install']['output'] = trim($buffered);
        }
        if ($code !== 0) {
            if (!$jsonMode) {
                $this->warn("Cert issued. Install failed (exit {$code}). Re-run manually once the vhost config is in place:");
                $this->out("  ubxcert install --domain {$baseDomain} --webserver {$ws} --conf /path/to/{$baseDomain}.conf");
            }
            if ($jsonMode) {
                $payload = $this->buildChallengeOutput($state) + $chainResult;
                $payload['auto_chain'] = $chainResult;
                $payload['domain']     = $baseDomain;
                $payload['status']     = 'auto-chain-failed';
                $payload['error_code'] = 'install_failed';
                $payload['error']      = "Auto-chain install step failed (exit {$code}).";
                $this->outputJson($payload);
            }
            return $code;
        }

        if (!$jsonMode) {
            $this->success("Auto-chain complete: cert installed on {$ws} for {$baseDomain}.");
            $this->out('  Cert dir   : ' . $this->state->getCertDir($baseDomain));
            $this->out('  LE symlink : /etc/letsencrypt/live/' . $baseDomain);
        }

        if ($jsonMode) {
            $payload = $this->buildChallengeOutput($state) + $chainResult;
            $payload['auto_chain'] = $chainResult;
            $payload['domain']     = $baseDomain;
            $payload['status']     = 'auto-chain-complete';
            // In --auto --json mode, the chain IS the next step; suppress
            // the original "complete ..." command string.
            unset($payload['next_step']);
            $this->outputJson($payload);
        }
        return 0;
    }

    // -------------------------------------------------------------------------
    // Challenge record builder
    // -------------------------------------------------------------------------

    /**
     * Build the per-domain challenge record stored in state.json.
     *
     * For DNS-01:
     *   - challenge_host: _acme-challenge.<domain>
     *   - txt_value:      base64url(sha256(key_authorization))
     *   - key_authorization: token + "." + thumbprint (also kept for parity)
     *
     * For HTTP-01:
     *   - http_path:        http://<domain>/.well-known/acme-challenge/<token>
     *   - key_authorization: token + "." + thumbprint  (served verbatim)
     *   - token:            from server
     */
    private function buildChallengeRecord(
        string    $challengeKind,
        string    $domain,
        string    $authStatus,
        string    $authzUrl,
        array     $acmeChallenge,
        \Ubxty\UbxCert\Acme\JwsHelper $jws
    ): array {
        $token = $acmeChallenge['token'];

        if ($challengeKind === self::CHALLENGE_HTTP) {
            $keyAuth = $jws->computeKeyAuthorization($token);
            return [
                'domain'           => $domain,
                'challenge_type'   => 'http-01',
                'token'            => $token,
                'key_authorization'=> $keyAuth,
                'http_url'         => "http://{$domain}/.well-known/acme-challenge/{$token}",
                'challenge_path'   => "/.well-known/acme-challenge/{$token}",
                'challenge_url'    => $acmeChallenge['url'],
                'authz_url'        => $authzUrl,
                'status'           => $authStatus,
            ];
        }

        // DNS-01 (default)
        $challengeBase  = ltrim($domain, '*.');
        $challengeHost  = "_acme-challenge.{$challengeBase}";
        $txtValue       = $jws->computeDnsTxtValue($token);
        $keyAuth        = $token . '.' . $jws->getThumbprint();

        return [
            'domain'            => $domain,
            'challenge_type'    => 'dns-01',
            'challenge_host'    => $challengeHost,
            'txt_value'         => $txtValue,
            'token'             => $token,
            'key_authorization' => $keyAuth,
            'challenge_url'     => $acmeChallenge['url'],
            'authz_url'         => $authzUrl,
            'status'            => $authStatus,
        ];
    }

    // -------------------------------------------------------------------------
    // Output
    // -------------------------------------------------------------------------

    private function outputChallenges(array $state): int
    {
        if ($this->jsonMode) {
            $payload = $this->buildChallengeOutput($state);
            $payload['status'] = 'ready';
            $this->outputJson($payload);
            return 0;
        }

        $type     = $state['challenge_type'] ?? self::CHALLENGE_DNS;
        $isHttp   = $type === self::CHALLENGE_HTTP;

        $this->out('');
        if ($isHttp) {
            $this->out('╔══════════════════════════════════════════════════════════╗');
            $this->out('║         HTTP-01 Challenge — Serve These Files            ║');
            $this->out('╚══════════════════════════════════════════════════════════╝');
        } else {
            $this->out('╔══════════════════════════════════════════════════════════╗');
            $this->out('║          DNS-01 Challenge — Add These TXT Records        ║');
            $this->out('╚══════════════════════════════════════════════════════════╝');
        }

        $seen = [];
        foreach ($state['challenges'] as $c) {
            if ($isHttp) {
                $key = ($c['http_url'] ?? '') . '|' . ($c['key_authorization'] ?? '');
            } else {
                $key = ($c['challenge_host'] ?? '') . '|' . ($c['txt_value'] ?? '');
            }
            if (in_array($key, $seen, true)) {
                continue;
            }
            $seen[] = $key;

            $this->out('');
            $this->out("  Domain       : {$c['domain']}");
            if ($isHttp) {
                $this->out("  URL          : {$c['http_url']}");
                $this->out("  Serve body   : {$c['key_authorization']}");
            } else {
                $this->out("  TXT Name     : {$c['challenge_host']}");
                $this->out("  TXT Value    : {$c['txt_value']}");
            }
        }

        $this->out('');
        if ($isHttp) {
            $this->out("Serve the body above at the URL on the domain itself (port 80), then run:");
            $this->out("  ubxcert complete --domain {$state['domain']} --challenge http --wait-http 60" . ($this->staging ? ' --staging' : ''));
        } else {
            $this->out("Add the TXT record(s) above to DNS, then run:");
            $this->out("  ubxcert complete --domain {$state['domain']} --wait-dns 600" . ($this->staging ? ' --staging' : ''));
        }
        $this->out('');

        return 0;
    }

    private function buildChallengeOutput(array $state): array
    {
        $type   = $state['challenge_type'] ?? self::CHALLENGE_DNS;
        $isHttp = $type === self::CHALLENGE_HTTP;

        $challengeEntries = array_map(function ($c) use ($isHttp) {
            if ($isHttp) {
                return [
                    'domain'            => $c['domain'],
                    'challenge_type'    => 'http-01',
                    'token'             => $c['token'],
                    'key_authorization' => $c['key_authorization'],
                    'http_url'          => $c['http_url'],
                    'challenge_path'    => $c['challenge_path'],
                    'status'            => $c['status'],
                ];
            }
            return [
                'domain'         => $c['domain'],
                'challenge_type' => 'dns-01',
                'challenge_host' => $c['challenge_host'],
                'txt_value'      => $c['txt_value'],
                'token'          => $c['token'],
                'status'         => $c['status'],
            ];
        }, $state['challenges']);

        $next = $isHttp
            ? "ubxcert complete --domain {$state['domain']} --challenge http --wait-http 60" . ($state['staging'] ? ' --staging' : '')
            : "ubxcert complete --domain {$state['domain']}" . ($state['staging'] ? ' --staging' : '');

        $payload = [
            'domain'         => $state['domain'],
            'domains'        => $state['domains'],
            'domain_count'   => count($state['domains'] ?? []),
            'primary_domain' => $state['domain'],
            'multi_domain'   => count($state['domains'] ?? []) > 1,
            'staging'        => $state['staging'],
            'challenge_type' => $type,
            'order_status'   => $state['order_status'],
            'challenges'     => $challengeEntries,
            'state_path'     => $this->state->getOrderDir($state['domain']) . '/state.json',
            'next_step'      => $next,
        ];

        if ($isHttp && isset($state['auto_webroot']) && is_array($state['auto_webroot'])) {
            $payload['auto_webroot'] = $state['auto_webroot'];
        }

        return $payload;
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    private function extractBaseDomain(array $domains): string
    {
        foreach ($domains as $d) {
            if (!str_starts_with($d, '*.')) {
                return $d;
            }
        }
        return ltrim($domains[0], '*.');
    }
}
