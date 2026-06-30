<?php

declare(strict_types=1);

namespace Ubxty\UbxCert\Commands;

/**
 * ubxcert update
 *
 * Friendly short alias for `ubxcert self-update`. The only
 * behavioural difference is that when a newer version is detected
 * on an interactive terminal, this command prompts the operator
 * for confirmation before running the install.
 *
 *   ubxcert update           # check + interactive y/N prompt
 *   ubxcert update --yes     # skip prompt, apply if newer
 *   ubxcert update --check   # print version info, do not install
 *   ubxcert update --force   # re-install even if up-to-date
 *
 * Behavioural notes:
 *  - In a non-TTY context (cron, piped output) the prompt is
 *    skipped entirely — the operator must pass --yes explicitly.
 *  - --json suppresses the prompt and emits the same JSON shape as
 *    `self-update`.
 *  - --check always short-circuits before the prompt.
 *  - When already on the latest version, no prompt is shown.
 */
class UpdateCommand extends BaseCommand
{
    public function getName(): string        { return 'update'; }
    public function getDescription(): string { return 'Update ubxcert (shortcut for `self-update` with y/N prompt)'; }

    public function run(array $args): int
    {
        $this->parseCommonArgs($args);

        // Snapshot flag state BEFORE consuming flags, so the delegated
        // SelfUpdateCommand still sees them in its own $args.
        $yes       = in_array('--yes',   $args, true) || in_array('-y',  $args, true);
        $checkOnly = in_array('--check', $args, true);
        $force     = in_array('--force', $args, true);

        // --check, --json, --yes short-circuit any prompt. Non-TTY does too.
        $isInteractive = !$checkOnly
                      && !$this->jsonMode
                      && !$yes
                      && self::isInteractiveTty();

        // Run the canonical self-update so version-comparison, network
        // calls, root check, and install logic stay in one place.
        $selfUpdate = new SelfUpdateCommand();

        // If we are going to need the prompt, we have to peek at the
        // current vs latest before delegating. Easier: delegate to
        // SelfUpdateCommand::run() directly — but it doesn't expose
        // a "would-I-update" predicate. Simplest correct path: re-run
        // the version check here and only delegate the install step.
        //
        // To keep zero duplication we wrap SelfUpdateCommand and ask
        // the user before calling its run(). When the user declines,
        // we exit 0 without doing anything.
        if (!$isInteractive) {
            return $selfUpdate->run($args);
        }

        // Interactive path: ask first, then run.
        $current = $selfUpdate->getCurrentVersionPublic();
        $latest  = $selfUpdate->fetchLatestVersionPublic();

        if ($latest === null) {
            // Could not determine a latest version — defer to the
            // canonical command which will print the right error.
            return $selfUpdate->run($args);
        }

        $isNewer = version_compare($latest, $current, '>');

        echo "\n";
        echo "  \033[1mubxcert version check\033[0m\n";
        echo '  ' . str_repeat('─', 44) . "\n";
        printf("  Installed : \033[36mv%s\033[0m\n", $current);
        printf("  Latest    : \033[36mv%s\033[0m\n", $latest);
        echo "\n";

        if (!$isNewer) {
            if (!$force) {
                $this->success("ubxcert is already up-to-date (v{$current}).");
                return 0;
            }
            // --force with no update available: still ask before re-installing.
        }

        printf(
            "  A new version is available: \033[32mv%s\033[0m (current \033[36mv%s\033[0m).\n",
            $latest,
            $current
        );
        echo "  Update now? [\033[1my\033[0m/N] ";

        $answer = self::readLine();
        $answer = is_string($answer) ? strtolower(trim($answer)) : '';

        if ($answer !== 'y' && $answer !== 'yes') {
            echo "  \033[2mUpdate declined — staying on v{$current}.\033[0m\n\n";
            return 0;
        }

        echo "\n";
        return $selfUpdate->run($args);
    }

    /**
     * Return true only when both stdin AND stdout are real terminals.
     * Detecting a TTY is the standard "interactive prompt" gate —
     * cron, `| cat`, `> file`, `nohup`, etc. all flip this off.
     */
    private static function isInteractiveTty(): bool
    {
        if (function_exists('posix_isatty')) {
            return @posix_isatty(STDIN) && @posix_isatty(STDOUT);
        }
        // Fallback: check that STDIN is not closed / redirected
        // Best-effort only.
        if (defined('STDIN')) {
            $stat = @fstat(STDIN);
            if (is_array($stat)) {
                $mode = $stat['mode'] ?? 0;
                // Character device (S_IFCHR = 020000)
                return ($mode & 0170000) === 020000;
            }
        }
        return false;
    }

    /**
     * Read one line from STDIN. Strips the trailing newline.
     * Returns the line, or null on EOF / closed stream.
     */
    private static function readLine(): ?string
    {
        $line = @fgets(STDIN);
        if ($line === false) {
            return null;
        }
        return rtrim($line, "\r\n");
    }
}