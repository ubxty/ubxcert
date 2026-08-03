<?php
declare(strict_types=1);

/**
 * Smoke test: --json mode always emits a single JSON document with
 * `challenges` and `status` keys, structured failures include `error_code`.
 *
 * Run: php tests/smoke_json_output.php
 * Exits 0 on success, 1 on first failure.
 *
 * Uses a minimal PSR-4 autoloader so we don't need composer install.
 */

spl_autoload_register(function (string $class) {
    $prefix = 'Ubxty\\UbxCert\\';
    if (!str_starts_with($class, $prefix)) {
        return;
    }
    $rel = substr($class, strlen($prefix));
    $path = __DIR__ . '/../src/' . str_replace('\\', '/', $rel) . '.php';
    if (file_exists($path)) {
        require $path;
    }
});

use Ubxty\UbxCert\Commands\BaseCommand;
use Ubxty\UbxCert\Commands\RequestCommand;

$failures = [];

function check(string $name, bool $ok, string $detail = ''): void
{
    global $failures;
    if ($ok) {
        echo "✓ {$name}\n";
    } else {
        echo "✗ {$name}  {$detail}\n";
        $failures[] = $name;
    }
}

// --- 1. outputJson() always returns single JSON document with challenges/status
$cmd = new class extends BaseCommand {
    public function getName(): string { return 'smoke'; }
    public function getDescription(): string { return 'smoke'; }
    public function run(array $args): int { return 0; }
};

$rc = new ReflectionMethod($cmd, 'outputJson');
$rc->setAccessible(true);

// turn on json mode via reflection
$jp = new ReflectionProperty($cmd, 'jsonMode');
$jp->setAccessible(true);
$jp->setValue($cmd, true);

// capture stdout
ob_start();
$rc->invoke($cmd, ['domain' => 'example.com']);
$out = ob_get_clean();

$decoded = json_decode($out, true);
check(
    'outputJson emits a single JSON document',
    $decoded !== null && json_last_error() === JSON_ERROR_NONE,
    "raw=" . var_export($out, true)
);
check(
    'outputJson includes `challenges` key',
    is_array($decoded) && array_key_exists('challenges', $decoded),
    'decoded=' . json_encode($decoded)
);
check(
    "outputJson default status is 'ok'",
    is_array($decoded) && ($decoded['status'] ?? null) === 'ok',
    'status=' . ($decoded['status'] ?? '(missing)')
);

// --- 2. outputJson merges captured messages
$jp->setValue($cmd, true);
$out_m = new ReflectionMethod($cmd, 'out');
$out_m->setAccessible(true);
$out_m->invoke($cmd, 'first message');
$warn_m = new ReflectionMethod($cmd, 'warn');
$warn_m->setAccessible(true);
$warn_m->invoke($cmd, 'uh oh');

ob_start();
$rc->invoke($cmd, ['domain' => 'example.com']);
$out = ob_get_clean();
$decoded = json_decode($out, true);
check(
    'outputJson captures messages emitted before it',
    is_array($decoded)
        && isset($decoded['messages'])
        && count($decoded['messages']) >= 2,
    'messages=' . json_encode($decoded['messages'] ?? null)
);

// --- 3. emitErrorJson emits structured failure envelope
$em = new ReflectionMethod($cmd, 'emitErrorJson');
$em->setAccessible(true);
$jp->setValue($cmd, true);

ob_start();
$em->invoke($cmd, 'no_challenge_offered', 'message text', ['extra' => 1]);
$out = ob_get_clean();
$decoded = json_decode($out, true);
check(
    'emitErrorJson emits JSON',
    $decoded !== null && json_last_error() === JSON_ERROR_NONE,
    'raw=' . var_export($out, true)
);
check(
    'emitErrorJson sets status=error',
    ($decoded['status'] ?? null) === 'error',
    'status=' . ($decoded['status'] ?? '(missing)')
);
check(
    'emitErrorJson sets error_code',
    ($decoded['error_code'] ?? null) === 'no_challenge_offered',
    'error_code=' . ($decoded['error_code'] ?? '(missing)')
);
check(
    'emitErrorJson includes messages',
    isset($decoded['messages']) && is_array($decoded['messages']),
    'messages=' . json_encode($decoded['messages'] ?? null)
);
check(
    'emitErrorJson merges extra fields',
    ($decoded['extra'] ?? null) === 1,
    'extra=' . json_encode($decoded['extra'] ?? null)
);

// --- 4. emitErrorJson in non-JSON mode just calls fail() to stderr (no JSON)
$jp->setValue($cmd, false);
ob_start();
$em->invoke($cmd, 'no_challenge_offered', 'just-text');
$out = ob_get_clean();
check(
    'emitErrorJson in human mode does not emit JSON',
    trim($out) === '',
    'out=' . var_export($out, true)
);

// --- 5. RequestCommand::buildChallengeOutput always has challenges
$bco = new ReflectionMethod(RequestCommand::class, 'buildChallengeOutput');
$bco->setAccessible(true);

$req = new RequestCommand();
$sample = [
    'domain'          => 'example.com',
    'domains'         => ['example.com'],
    'staging'         => false,
    'challenge_type'  => 'http',
    'order_status'    => 'pending',
    'challenges'      => [
        [
            'domain'            => 'example.com',
            'challenge_type'    => 'http-01',
            'token'             => 'tok',
            'key_authorization' => 'tok.thumb',
            'http_url'          => 'http://example.com/.well-known/acme-challenge/tok',
            'challenge_path'    => '/.well-known/acme-challenge/tok',
            'status'            => 'pending',
        ],
    ],
];

$built = $bco->invoke($req, $sample);
check(
    'buildChallengeOutput includes challenges',
    isset($built['challenges']) && count($built['challenges']) === 1,
    'built=' . json_encode($built)
);

// --- 6. buildChallengeOutput emits multi-domain batch metadata (#1)
$multi = $sample;
$multi['domains'] = ['example.com', 'www.example.com', 'api.example.com'];
$builtMulti = $bco->invoke($req, $multi);
check(
    'buildChallengeOutput sets domain_count',
    ($builtMulti['domain_count'] ?? null) === 3,
    'domain_count=' . ($builtMulti['domain_count'] ?? '(missing)')
);
check(
    'buildChallengeOutput sets multi_domain=true',
    ($builtMulti['multi_domain'] ?? null) === true,
    'multi_domain=' . json_encode($builtMulti['multi_domain'] ?? null)
);
check(
    'buildChallengeOutput sets primary_domain',
    ($builtMulti['primary_domain'] ?? null) === 'example.com',
    'primary_domain=' . ($builtMulti['primary_domain'] ?? '(missing)')
);

// --- 7. Config class reads /etc/ubxcert/config.json (#5)
use Ubxty\UbxCert\Config\Config;
$tmpConfig = tempnam(sys_get_temp_dir(), 'ubxcert-cfg-');
file_put_contents($tmpConfig . '.json', json_encode([
    'default_staging' => true,
    'renewal_days_before' => 45,
    'cloudflare' => ['api_token' => 'secret', 'zone_id' => 'Z'],
]));
@unlink($tmpConfig);
$cfg = new Config($tmpConfig . '.json');
@rename($tmpConfig, $tmpConfig . '.json');
check(
    'Config reads default_staging=true',
    $cfg->get('default_staging') === true,
    'got=' . var_export($cfg->get('default_staging'), true)
);
check(
    'Config reads renewal_days_before=45',
    $cfg->get('renewal_days_before') === 45,
    'got=' . var_export($cfg->get('renewal_days_before'), true)
);
check(
    'Config reads nested cloudflare.zone_id',
    $cfg->get('cloudflare')['zone_id'] === 'Z',
    'cf=' . json_encode($cfg->get('cloudflare'))
);
@unlink($tmpConfig . '.json');

// --- 8. Quiet events parseCommonArgs flag (#16)
$quietCmd = new class extends BaseCommand {
    public function getName(): string { return 'quiet'; }
    public function getDescription(): string { return 'q'; }
    public function run(array $args): int { return 0; }
};
$qpca = new ReflectionMethod($quietCmd, 'parseCommonArgs');
$qpca->setAccessible(true);
$args = ['--quiet-events', '--json'];
$qpca->invokeArgs($quietCmd, [&$args]);
$qp = new ReflectionProperty($quietCmd, 'quietEvents');
$qp->setAccessible(true);
check(
    'parseCommonArgs handles --quiet-events',
    $qp->getValue($quietCmd) === true,
    'quietEvents=' . var_export($qp->getValue($quietCmd), true)
);

$args2 = ['--no-staging'];
$noStagingCmd = new class extends BaseCommand {
    public function getName(): string { return 'ns'; }
    public function getDescription(): string { return 'ns'; }
    public function run(array $args): int { return 0; }
};
$qpca2 = new ReflectionMethod($noStagingCmd, 'parseCommonArgs');
$qpca2->setAccessible(true);
$qpca2->invokeArgs($noStagingCmd, [&$args2]);
$sp = new ReflectionProperty($noStagingCmd, 'staging');
$sp->setAccessible(true);
check(
    'parseCommonArgs handles --no-staging',
    $sp->getValue($noStagingCmd) === false,
    'staging=' . var_export($sp->getValue($noStagingCmd), true)
);

// --- 9. CompleteCommand must never leave $challenge undefined after the
// HTTP-01 / DNS-01 poll loops. The old code used `foreach (… as &$challenge)`
// inside the loops, which clobbered the outer $challenge (set on line 87
// from `$stateChallenge`) once `unset($challenge)` ran. The success path
// then printed `Warning: Undefined variable $challenge` on stdout, which
// poisoned the JSON document and made the panel's `json.load` choke.
//
// Fix: the loops now bind to `$ch` so the outer `$challenge` survives.
$completeSrc = file_get_contents(__DIR__ . '/../src/Commands/CompleteCommand.php');
check(
    'CompleteCommand does not bind foreach as &$challenge',
    !str_contains($completeSrc, 'foreach ($state[\'challenges\'] as &$challenge)'),
    'found `&$challenge` reference — leaks into outer scope and steals the variable'
);
check(
    'CompleteCommand does not unset($challenge) outside a loop var',
    !preg_match('/unset\(\$challenge\)/', $completeSrc),
    'found unset($challenge) — would destroy the outer $challenge'
);
check(
    'CompleteCommand retains $challenge = $stateChallenge on success path',
    str_contains($completeSrc, '$challenge = $stateChallenge;'),
    'lost the $stateChallenge reboot'
);
check(
    'CompleteCommand emits challenge_type in JSON output',
    str_contains($completeSrc, "'challenge_type'   => \$challenge"),
    'JSON output still references $challenge'
);

// --- 10. BaseCommand silences PHP diagnostics in --json mode. Without
// this guard, a stray warning (e.g. "Undefined variable $challenge" on
// line 265 of CompleteCommand, or a PHP 8.4 deprecation notice) prints
// to stdout and lands before the JSON document. The panel's `json.load`
// then fails on the leading warning line. The fix is centralized in
// BaseCommand::parseCommonArgs so every command that accepts --json is
// protected in one place.
$baseSrc = file_get_contents(__DIR__ . '/../src/Commands/BaseCommand.php');
check(
    'BaseCommand defines silencePhpDiagnosticsForJson()',
    str_contains($baseSrc, 'function silencePhpDiagnosticsForJson('),
    'helper missing — JSON mode can leak warnings to stdout'
);
check(
    'parseCommonArgs invokes silencePhpDiagnosticsForJson when --json is seen',
    (bool) preg_match(
        "/if \(\\\$arg === '--json'\) \\{\\s*\\\$this->jsonMode = true;\\s*\\\$this->silencePhpDiagnosticsForJson\\(\\);/m",
        $baseSrc
    ),
    'parseCommonArgs does not gate the silence call on --json'
);

// --- 11. runAutoChain must not pass --json to inner sub-commands. The
// auto-chain is run when --json is on the outer request, and a second
// JSON document from the inner complete/install call would land on the
// same stdout stream and corrupt the panel's `json.load`. Sub-commands
// are now captured into the envelope's chainResult[*].output field
// via ob_start/ob_get_clean instead.
$reqSrc = file_get_contents(__DIR__ . '/../src/Commands/RequestCommand.php');
$autoChainRegion = substr($reqSrc, (int) strpos($reqSrc, 'function runAutoChain'));
check(
    'runAutoChain does not pass --json to inner CompleteCommand',
    !str_contains($autoChainRegion, '$completeArgs[] = \'--json\''),
    'inner --json would produce a second JSON document on stdout'
);
check(
    'runAutoChain does not pass --json to inner InstallWebserverCommand',
    !str_contains($autoChainRegion, '$installArgs[] = \'--json\''),
    'inner --json would produce a second JSON document on stdout'
);
check(
    'runAutoChain captures inner sub-command stdout via ob_start',
    str_contains($autoChainRegion, 'ob_start()')
        && str_contains($autoChainRegion, 'ob_get_clean()'),
    'sub-command stdout must be buffered so it does not pollute the auto-chain JSON envelope'
);
check(
    'runAutoChain exposes inner output via chainResult[*].output',
    str_contains($autoChainRegion, "\$chainResult['complete']['output']")
        && str_contains($autoChainRegion, "\$chainResult['install']['output']"),
    'operator should still see inner command output in the envelope'
);

// --- 12. CompleteCommand short-circuits when the order is already valid
// AND a saved fullchain.pem exists. The panel shell calls `ubxcert complete`
// even after auto-chain has finalized and downloaded the cert. Without this
// guard, the re-run would POST to the ACME finalize endpoint again and
// surface a "SSL generation error" to the operator. The guard returns
// status='already-valid' in JSON mode so the panel can distinguish a true
// re-run from a no-op.
check(
    'CompleteCommand has idempotency guard for already-valid orders',
    str_contains($completeSrc, "'order_status'] ?? null) === 'valid'")
        && str_contains($completeSrc, 'is_file($certDir . \'/fullchain.pem\')'),
    're-running `complete` on an already-valid order would re-finalize and fail at the ACME server'
);
check(
    'CompleteCommand idempotency guard returns status=already-valid in JSON',
    str_contains($completeSrc, "'status'           => 'already-valid'"),
    'panel needs to distinguish a no-op re-run from a fresh complete'
);

// --- 13. ListCommand buildRow surfaces rich X.509 metadata so the panel
// can verify SSL is installed AND configured correctly on the running
// webserver. The fields below are populated from openssl_x509_parse +
// openssl_pkey_get_details — without them the operator only sees the
// domain, expiry date, and webserver install status.
$listSrc = file_get_contents(__DIR__ . '/../src/Commands/ListCommand.php');
$expectedKeys = [
    'issuer',
    'subject',
    'serial',
    'signature_algorithm',
    'key_algorithm',
    'key_size',
    'fingerprint_sha256',
    'valid_from',
    'valid_to',
    "'vhost'",
];
foreach ($expectedKeys as $key) {
    check(
        "ListCommand::buildRow surfaces `{$key}` for the panel",
        str_contains($listSrc, $key),
        "buildRow must include `{$key}` in its return array; the panel reads it from ubxcert list --json"
    );
}

// --- 14. ListCommand::readCertInfo uses the PHP openssl extension to
// extract issuer/subject/serial/key-info — i.e. no shell-out, no
// dependency on the `openssl` binary being on PATH.
check(
    'ListCommand::readCertInfo parses issuer + subject via openssl_x509_parse',
    str_contains($listSrc, "openssl_x509_parse(\$cert)")
        && str_contains($listSrc, '$info[\'issuer\']')
        && str_contains($listSrc, '$info[\'subject\']'),
    'readCertInfo must read issuer/subject from openssl_x509_parse output'
);
check(
    'ListCommand::readCertInfo extracts key algorithm + size via openssl_pkey_get_details',
    str_contains($listSrc, 'openssl_pkey_get_public($cert)')
        && str_contains($listSrc, 'openssl_pkey_get_details'),
    'key_algorithm + key_size require openssl_pkey_get_details; openssl_x509_parse alone is not enough'
);
check(
    'ListCommand::readCertInfo computes SHA-256 fingerprint from PEM body',
    str_contains($listSrc, "hash('sha256', \$der)")
        || str_contains($listSrc, 'hash(\'sha256\', $der)'),
    'fingerprint_sha256 must be the SHA-256 hash of the DER-encoded cert, formatted colon-separated'
);

// --- 15. VhostScanner extends parseNginx to extract the SSL wiring the
// operator cares about: ssl_protocols, http2_enabled, hsts_header,
// wellknown_handler. Without these the sync response can only say
// "cert is installed on openresty" but not "openresty is listening on
// 443 with HTTP/2 + HSTS + lua-resty-acme fallback".
$vhostSrc = file_get_contents(__DIR__ . '/../src/Util/VhostScanner.php');
$vhostExpected = ['ssl_protocols', 'http2_enabled', 'hsts_header', 'wellknown_handler'];
foreach ($vhostExpected as $key) {
    check(
        "VhostScanner::parseNginx populates `{$key}` on each entry",
        str_contains($vhostSrc, "'{$key}'"),
        "parseNginx must set `{$key}` on every entry; downstream parsers consume it"
    );
}
check(
    'VhostScanner::domainSslWebserverDetails is a public method returning an array',
    preg_match('/public static function domainSslWebserverDetails\s*\([^)]+\)\s*:\s*\?array/', $vhostSrc) === 1,
    'ListCommand::discoverAll calls VhostScanner::domainSslWebserverDetails($domain) to pull vhost inspection into each row'
);

if ($failures) {
    echo "\nFAILED: " . count($failures) . " check(s)\n";
    exit(1);
}

echo "\nALL OK\n";
exit(0);
