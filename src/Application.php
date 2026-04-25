<?php

declare(strict_types=1);

namespace Ubxty\UbxCert;

use Throwable;
use Ubxty\UbxCert\Commands\BaseCommand;
use Ubxty\UbxCert\Commands\CompleteCommand;
use Ubxty\UbxCert\Commands\InstallWebserverCommand;
use Ubxty\UbxCert\Commands\ListCommand;
use Ubxty\UbxCert\Commands\RenewCommand;
use Ubxty\UbxCert\Commands\RequestCommand;
use Ubxty\UbxCert\Commands\StatusCommand;

/**
 * ubxcert CLI application router.
 *
 * Dispatches argv to the appropriate command.
 */
class Application
{
    private const VERSION = '1.0.0';

    /** @var BaseCommand[] */
    private array $commands = [];

    public function __construct()
    {
        $this->register(new RequestCommand());
        $this->register(new CompleteCommand());
        $this->register(new InstallWebserverCommand());
        $this->register(new RenewCommand());
        $this->register(new ListCommand());
        $this->register(new StatusCommand());
    }

    private function register(BaseCommand $cmd): void
    {
        $this->commands[$cmd->getName()] = $cmd;
    }

    /**
     * @param string[] $argv
     */
    public function run(array $argv): int
    {
        $commandName = $argv[1] ?? null;
        $args        = array_slice($argv, 2);

        if ($commandName === null || in_array($commandName, ['help', '--help', '-h'], true)) {
            $this->printHelp();
            return 0;
        }

        if (in_array($commandName, ['version', '--version', '-V'], true)) {
            echo "ubxcert " . self::VERSION . "\n";
            return 0;
        }

        if (!isset($this->commands[$commandName])) {
            fwrite(STDERR, "ubxcert: unknown command '{$commandName}'\n\n");
            $this->printHelp();
            return 1;
        }

        try {
            return $this->commands[$commandName]->run($args);
        } catch (Throwable $e) {
            fwrite(STDERR, "\033[31mubxcert error: " . $e->getMessage() . "\033[0m\n");
            if (in_array('--verbose', $args, true) || in_array('-v', $args, true)) {
                fwrite(STDERR, $e->getTraceAsString() . "\n");
            }
            return 1;
        }
    }

    private function printHelp(): void
    {
        echo "ubxcert v" . self::VERSION . " — ACME v2 certificate manager (replaces certbot)\n\n";
        echo "Usage: ubxcert <command> [options]\n\n";
        echo "Commands:\n";

        foreach ($this->commands as $cmd) {
            echo sprintf("  %-12s %s\n", $cmd->getName(), $cmd->getDescription());
        }

        echo "\nGlobal options:\n";
        echo "  --staging   Use Let's Encrypt staging environment\n";
        echo "  --json      Output JSON (for shell script integration)\n";
        echo "  --verbose   Show detailed progress\n";
        echo "\nExamples:\n";
        echo "  ubxcert request --domains \"*.example.com,example.com\" --email admin@example.com\n";
        echo "  ubxcert complete --domain example.com --wait-dns 600\n";
        echo "  ubxcert install --domain example.com --webserver openresty\n";
        echo "  ubxcert renew --all --days-before 30\n";
        echo "  ubxcert list\n";
        echo "  ubxcert status --domain example.com\n";
    }
}
