<?php

declare(strict_types=1);

namespace Ubxty\UbxCert\Commands;

use Ubxty\UbxCert\Acme\AcmeClient;
use Ubxty\UbxCert\Acme\JwsHelper;
use Ubxty\UbxCert\Cert\CertificateManager;
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
    // Output helpers
    // -------------------------------------------------------------------------

    protected function out(string $msg): void
    {
        if (!$this->jsonMode) {
            echo $msg . "\n";
        }
    }

    protected function err(string $msg): void
    {
        fwrite(STDERR, $msg . "\n");
    }

    protected function verbose(string $msg): void
    {
        if ($this->verbose && !$this->jsonMode) {
            echo "  {$msg}\n";
        }
    }

    protected function success(string $msg): void
    {
        $this->out("\033[32m✓ {$msg}\033[0m");
    }

    protected function warn(string $msg): void
    {
        $this->out("\033[33m⚠ {$msg}\033[0m");
    }

    protected function fail(string $msg): void
    {
        $this->err("\033[31m✗ {$msg}\033[0m");
    }

    protected function outputJson(array $data): void
    {
        echo json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) . "\n";
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
