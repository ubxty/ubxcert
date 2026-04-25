<?php

declare(strict_types=1);

namespace Ubxty\UbxCert;

/**
 * Simple append-only file logger for ubxcert operations.
 *
 * Writes structured lines to /var/log/ubxcert/ubxcert.log.
 * Rotates (renames to .1) when the log exceeds 10 MB.
 * All errors are swallowed — log failures must never crash the CLI.
 */
class Logger
{
    private const LOG_DIR   = '/var/log/ubxcert';
    private const LOG_FILE  = '/var/log/ubxcert/ubxcert.log';
    private const MAX_BYTES = 10 * 1024 * 1024; // 10 MB

    public static function write(string $level, string $command, string $message): void
    {
        try {
            if (!is_dir(self::LOG_DIR)) {
                @mkdir(self::LOG_DIR, 0700, true);
            }

            if (file_exists(self::LOG_FILE) && filesize(self::LOG_FILE) > self::MAX_BYTES) {
                @rename(self::LOG_FILE, self::LOG_FILE . '.1');
            }

            $line = sprintf(
                "[%s] [%-5s] [%s] %s\n",
                date('Y-m-d H:i:s'),
                strtoupper($level),
                $command,
                $message
            );

            @file_put_contents(self::LOG_FILE, $line, FILE_APPEND | LOCK_EX);
        } catch (\Throwable) {
            // intentionally silent
        }
    }
}
