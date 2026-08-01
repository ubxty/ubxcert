<?php

declare(strict_types=1);

namespace Ubxty\UbxCert\Commands;

use Ubxty\UbxCert\Acme\AcmeClient;
use Ubxty\UbxCert\Acme\JwsHelper;
use Ubxty\UbxCert\Cert\CertificateManager;
use Ubxty\UbxCert\Logger;
use Ubxty\UbxCert\State\StateManager;

/**
 * Shared CLI helpers inherited by all commands.
 */
abstract class BaseCommand
{
    protected bool $jsonMode   = false;
    protected bool $verbose    = false;
    protected bool $staging    = false;

    protected StateManager      $state;
    protected CertificateManager $certs;

    public function __construct()
    {
        $this->state = new StateManager();
        $this->certs = new CertificateManager($this->state);
    }

    abstract public function getName(): string;

    abstract public function getDescription(): string;

    /** @param string[] $args argv after the command name */
    abstract public function run(array $args): int;

    // -------------------------------------------------------------------------
    // Logging
    // -------------------------------------------------------------------------

    /** Write a line to /var/log/ubxcert/ubxcert.log */
    protected function log(string $level, string $message): void
    {
        Logger::write($level, $this->getName(), $message);
    }

    // -------------------------------------------------------------------------
    // Output helpers
    // -------------------------------------------------------------------------

    /** Captured human output so it can be embedded in the final JSON document. */
    protected array $jsonMessages = [];

    protected function out(string $msg): void
    {
        if ($this->jsonMode) {
            $this->jsonMessages[] = ['level' => 'info', 'message' => $msg];
            return;
        }
        echo $msg . "\n";
    }

    protected function err(string $msg): void
    {
        fwrite(STDERR, $msg . "\n");
    }

    protected function verbose(string $msg): void
    {
        if (!$this->verbose) {
            return;
        }
        if ($this->jsonMode) {
            $this->jsonMessages[] = ['level' => 'verbose', 'message' => $msg];
            return;
        }
        echo "  {$msg}\n";
    }

    protected function success(string $msg): void
    {
        if ($this->jsonMode) {
            $this->jsonMessages[] = ['level' => 'success', 'message' => $msg];
            return;
        }
        $this->out("\033[32m✓ {$msg}\033[0m");
    }

    protected function warn(string $msg): void
    {
        if ($this->jsonMode) {
            $this->jsonMessages[] = ['level' => 'warn', 'message' => $msg];
            return;
        }
        $this->out("\033[33m⚠ {$msg}\033[0m");
    }

    protected function fail(string $msg): void
    {
        if ($this->jsonMode) {
            $this->jsonMessages[] = ['level' => 'error', 'message' => $msg];
            return;
        }
        $this->err("\033[31m✗ {$msg}\033[0m");
    }

    /**
     * Emit a single JSON document to stdout. In --json mode we guarantee
     * exactly one well-formed JSON object per invocation so that panel
     * wrappers can `$(...)` the output and `json.load` it without
     * stripping prose lines.
     */
    protected function outputJson(array $data): void
    {
        if ($this->jsonMode) {
            if (!array_key_exists('status', $data)) {
                $data['status'] = 'ok';
            }
            if (!array_key_exists('challenges', $data)) {
                // Always include `challenges` so consumers can do
                // `payload.get('challenges', [])` without a KeyError.
                $data['challenges'] = [];
            }
            if (!array_key_exists('messages', $data) && $this->jsonMessages) {
                $data['messages'] = $this->jsonMessages;
            }
        }
        echo json_encode($data, JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n";
    }

    /**
     * Emit a structured failure JSON document. Always returns a single
     * JSON object on stdout (in --json mode) with status='error' and a
     * stable `error_code`. Keeps any partial `challenges` and the
     * captured messages so the panel can debug without losing context.
     *
     * @param array<string, mixed> $extra  Additional fields to merge into
     *                                     the payload (e.g. auth_errors).
     */
    protected function emitErrorJson(string $errorCode, string $message, array $extra = []): void
    {
        if (!$this->jsonMode) {
            $this->fail($message);
            return;
        }

        $payload = ['status' => 'error', 'error_code' => $errorCode, 'error' => $message] + $extra;
        $this->outputJson($payload);
    }

    // -------------------------------------------------------------------------
    // Arg parsing
    // -------------------------------------------------------------------------

    protected function parseCommonArgs(array &$args): void
    {
        foreach ($args as $i => $arg) {
            if ($arg === '--json') {
                $this->jsonMode = true;
                unset($args[$i]);
            } elseif ($arg === '--staging') {
                $this->staging = true;
                unset($args[$i]);
            } elseif ($arg === '-v' || $arg === '--verbose') {
                $this->verbose = true;
                unset($args[$i]);
            }
        }
        $args = array_values($args);
    }

    /**
     * Extract a named option value from args: --option value or --option=value
     * Removes both the flag and value from the array.
     */
    protected function extractOption(array &$args, string $name): ?string
    {
        $dashes = '--' . ltrim($name, '-');
        foreach ($args as $i => $arg) {
            // --option=value form
            if (str_starts_with($arg, "{$dashes}=")) {
                $value = substr($arg, strlen($dashes) + 1);
                unset($args[$i]);
                $args = array_values($args);
                return $value;
            }
            // --option value form
            if ($arg === $dashes && isset($args[$i + 1])) {
                $value = $args[$i + 1];
                unset($args[$i], $args[$i + 1]);
                $args = array_values($args);
                return $value;
            }
        }
        return null;
    }

    protected function hasFlag(array &$args, string $name): bool
    {
        $dashes = '--' . ltrim($name, '-');
        foreach ($args as $i => $arg) {
            if ($arg === $dashes) {
                unset($args[$i]);
                $args = array_values($args);
                return true;
            }
        }
        return false;
    }

    // -------------------------------------------------------------------------
    // ACME helpers shared across commands
    // -------------------------------------------------------------------------

    /** Ensure/create account and return [JwsHelper, kid] */
    protected function resolveAccount(string $email): array
    {
        $jws    = JwsHelper::loadOrGenerate($this->state->getAccountKeyPath($email));
        $client = new AcmeClient($this->staging);

        $info = $this->state->loadAccountInfo($email);
        if ($info && isset($info['kid'])) {
            $this->verbose("Using existing ACME account: {$info['kid']}");
            return [$jws, $info['kid'], $client];
        }

        $this->verbose('Registering new ACME account...');
        $account = $client->createOrFindAccount($jws, $email);

        $this->state->saveAccountInfo($email, [
            'kid'        => $account['kid'],
            'email'      => $email,
            'staging'    => $this->staging,
            'created_at' => date('c'),
        ]);

        $this->verbose("Account registered: {$account['kid']}");
        return [$jws, $account['kid'], $client];
    }
}
