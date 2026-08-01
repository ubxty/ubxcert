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

if ($failures) {
    echo "\nFAILED: " . count($failures) . " check(s)\n";
    exit(1);
}

echo "\nALL OK\n";
exit(0);
