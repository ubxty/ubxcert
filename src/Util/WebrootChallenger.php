<?php

declare(strict_types=1);

namespace Ubxty\UbxCert\Util;

/**
 * Auto-write HTTP-01 ACME challenge files to a site's document root
 * and verify they are reachable from the public internet.
 *
 * The HTTP-01 challenge requires a web server to serve
 *
 *     http://<domain>/.well-known/acme-challenge/<token>
 *
 * with a body equal to `token + "." + thumbprint`. This utility:
 *
 *   1. Resolves the document root for the domain via VhostScanner.
 *   2. Writes the challenge file there with the correct permissions.
 *   3. Probes the public URL to confirm reachability.
 *   4. Returns a result struct callers can surface in JSON output
 *      and in the human-readable log.
 *
 * The class is dependency-free (no UB Panel objects) so it can be
 * invoked from both RequestCommand and CompleteCommand with no
 * ceremony.
 */
final class WebrootChallenger
{
    /** Default reachability timeout in seconds. */
    private const VERIFY_TIMEOUT = 15;

    /** Default body mode for the challenge file. */
    private const FILE_MODE = 0644;

    /** Default directory mode for the .well-known parent. */
    private const DIR_MODE  = 0755;

    /**
     * Write the HTTP-01 challenge file to the resolved docroot and
     * (optionally) verify that the public URL serves the expected body.
     *
     * Behaviour:
     *  - If `$explicitWebroot` is supplied, it overrides detection.
     *  - If no docroot can be resolved, returns a result with
     *    `wrote=false` and a human-readable `error`.
     *  - Never throws — always returns a struct so callers can
     *    decide whether to abort, warn, or continue.
     *
     * @return array{
     *   wrote:bool,
     *   docroot:?string,
     *   webserver:?string,
     *   file_path:?string,
     *   url:?string,
     *   verified:bool,
     *   verify_log:list<string>,
     *   error:?string,
     *   skipped:?string,
     * }
     */
    public static function write(
        string $domain,
        string $token,
        string $keyAuthorization,
        ?string $explicitWebroot = null,
        bool $requireVerification = true
    ): array {
        $log = [];
        $result = [
            'wrote'       => false,
            'docroot'     => null,
            'webserver'   => null,
            'file_path'   => null,
            'url'         => null,
            'verified'    => false,
            'verify_log'  => $log,
            'error'       => null,
            'skipped'     => null,
        ];

        $domain = strtolower(trim($domain));
        $token  = trim($token);
        if ($domain === '' || $token === '' || $keyAuthorization === '') {
            $result['error'] = 'Empty domain/token/key_authorization';
            return $result;
        }

        $url = "http://{$domain}/.well-known/acme-challenge/{$token}";
        $result['url'] = $url;

        // 1. Resolve docroot
        $docroot = null;
        $ws      = null;
        if ($explicitWebroot !== null && $explicitWebroot !== '') {
            if (!is_dir($explicitWebroot)) {
                $result['error'] = "Explicit --webroot '{$explicitWebroot}' does not exist or is not a directory.";
                return $result;
            }
            $docroot = rtrim($explicitWebroot, '/');
            $ws      = VhostScanner::detectPrimary();
            $log[]   = "Using explicit --webroot: {$docroot}";
        } else {
            $resolved = VhostScanner::resolveDocroot($domain);
            if ($resolved === null) {
                $result['error'] = "Could not detect a document root for '{$domain}'. "
                    . "Pass --webroot=/path/to/docroot or --no-auto-webroot to serve the file manually.";
                return $result;
            }
            $docroot = $resolved['docroot'];
            $ws      = $resolved['webserver'];
            $log[]   = "Auto-resolved docroot: {$docroot} (webserver: {$ws})";
        }

        $result['docroot']   = $docroot;
        $result['webserver'] = $ws;

        // Safety: refuse to write to /
        if ($docroot === '' || $docroot === '/' || $docroot === '/var' || $docroot === '/etc') {
            $result['error'] = "Refusing to write to unsafe docroot '{$docroot}'.";
            return $result;
        }

        $dir      = $docroot . '/.well-known/acme-challenge';
        $filePath = $dir . '/' . $token;

        // 2. Make the parent directory tree
        if (!is_dir($dir)) {
            if (!@mkdir($dir, self::DIR_MODE, true) && !is_dir($dir)) {
                $error          = error_get_last()['message'] ?? 'unknown error';
                $result['error'] = "Failed to create '{$dir}': {$error}";
                return $result;
            }
            $log[] = "Created directory: {$dir}";
        }

        // 3. Write the challenge body
        $written = @file_put_contents($filePath, $keyAuthorization, LOCK_EX);
        if ($written === false) {
            $error          = error_get_last()['message'] ?? 'unknown error';
            $result['error'] = "Failed to write '{$filePath}': {$error}";
            return $result;
        }
        @chmod($filePath, self::FILE_MODE);
        $log[]              = "Wrote {$written} bytes to {$filePath}";
        $result['wrote']    = true;
        $result['file_path'] = $filePath;

        // 4. Verify reachability (optional)
        if ($requireVerification) {
            $body = self::fetchHttpBody($url);
            if ($body === null) {
                $log[]               = "Verification failed: no 2xx response from {$url}";
                $result['verified']  = false;
                $result['error']     = "File written but ACME server could not reach it from outside — "
                    . "likely port 80 is blocked, DNS not propagated, or the webserver is not serving "
                    . "{$docroot}/.well-known/. The file is in place; retry 'ubxcert complete --wait-http 60'.";
                return $result;
            }
            if (trim($body) !== $keyAuthorization) {
                $log[]               = "Verification failed: body mismatch at {$url}";
                $log[]               = "  expected: {$keyAuthorization}";
                $log[]               = "  got     : " . trim($body);
                $result['verified']  = false;
                $result['error']     = "File written but a different body is being served — a default-server vhost "
                    . "may be intercepting /.well-known/. See 'ubxcert help request' for the manual-mode workaround.";
                return $result;
            }
            $log[]              = "Verified: body matches at {$url}";
            $result['verified'] = true;
        } else {
            $result['skipped'] = 'verification-skipped-by-caller';
        }

        return $result;
    }

    /**
     * Best-effort cleanup of the challenge file. Returns true if the
     * file was removed, false if it was already gone or unremovable.
     * Never throws.
     *
     * `$explicitDocroot` lets the caller pass back the docroot that
     * `write()` resolved — useful when `write()` was run with an
     * explicit `--webroot` that auto-detection would not rediscover
     * later (e.g. after the vhost config has changed).
     */
    public static function cleanup(string $domain, string $token, ?string $explicitDocroot = null): bool
    {
        $domain = strtolower(trim($domain));
        $token  = trim($token);
        if ($domain === '' || $token === '') {
            return false;
        }

        $docroot = self::resolveDocrootFor($domain, $explicitDocroot);
        if ($docroot === null) {
            return false;
        }

        $filePath = $docroot . '/.well-known/acme-challenge/' . $token;
        if (!is_file($filePath)) {
            return false;
        }
        return @unlink($filePath);
    }

    /**
     * Resolve the docroot path that `write()` / `cleanup()` would
     * target, without actually writing anything. Public so callers
     * (CompleteCommand's idempotency check, shutdown handlers) can
     * mirror `write()`'s resolution logic exactly.
     *
     * Returns the directory path, or null if neither an explicit
     * root nor a detected docroot is available.
     */
    public static function resolveDocrootFor(string $domain, ?string $explicitDocroot = null): ?string
    {
        $domain = strtolower(trim($domain));
        if ($explicitDocroot !== null && $explicitDocroot !== '') {
            if (is_dir($explicitDocroot)) {
                return rtrim($explicitDocroot, '/');
            }
            return null;
        }
        $resolved = VhostScanner::resolveDocroot($domain);
        return $resolved['docroot'] ?? null;
    }

    /**
     * GET an HTTP URL and return the body, or null on transport failure /
     * non-2xx status. Follows redirects. Mirrors CompleteCommand's
     * internal poller so behaviour is consistent across the two commands.
     */
    private static function fetchHttpBody(string $url): ?string
    {
        if (!function_exists('curl_init')) {
            return null;
        }

        $ch = curl_init($url);
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => true,
            CURLOPT_MAXREDIRS      => 5,
            CURLOPT_TIMEOUT        => self::VERIFY_TIMEOUT,
            CURLOPT_CONNECTTIMEOUT => 5,
            CURLOPT_HTTP_VERSION   => CURL_HTTP_VERSION_1_1,
            CURLOPT_USERAGENT      => 'ubxcert/1.1 (+https://github.com/ubxty/ubxcert) HTTP-01-auto-verifier',
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ]);

        $raw   = curl_exec($ch);
        $code  = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $error = curl_error($ch);
        curl_close($ch);

        if ($raw === false || $error !== '') {
            return null;
        }
        if ($code < 200 || $code >= 300) {
            return null;
        }
        return is_string($raw) ? $raw : null;
    }
}