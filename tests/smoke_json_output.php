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

if ($failures) {
    echo "\nFAILED: " . count($failures) . " check(s)\n";
    exit(1);
}

echo "\nALL OK\n";
exit(0);
