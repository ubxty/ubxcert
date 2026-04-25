<?php

declare(strict_types=1);

namespace Ubxty\UbxCert\Commands;

use Throwable;

/**
 * ubxcert install
 *
 * Installs a completed certificate into a web server vhost config and reloads.
 * Supports openresty, nginx, and apache2.
 *
 * Usage:
 *   ubxcert install --domain example.com --webserver openresty|nginx|apache
 */
class InstallWebserverCommand extends BaseCommand
{
    public function getName(): string        { return 'install'; }
    public function getDescription(): string { return 'Install certificate into web server vhost and reload'; }

    public function run(array $args): int
    {
        $this->parseCommonArgs($args);

        $domain    = $this->extractOption($args, 'domain');
        $webserver = $this->extractOption($args, 'webserver');
        $confPath  = $this->extractOption($args, 'conf');   // optional override for vhost path

        if (!$domain || !$webserver) {
            $this->fail('Usage: ubxcert install --domain example.com --webserver openresty|nginx|apache [--conf /path/to/vhost.conf]');
            return 1;
        }

        $certDir = $this->state->getCertDir($domain);

        if (!file_exists("{$certDir}/fullchain.pem")) {
            $this->fail("Certificate not found for {$domain}. Run 'ubxcert complete' first.");
            return 1;
        }

        $certFile = "{$certDir}/fullchain.pem";
        $keyFile  = "{$certDir}/privkey.pem";

        $this->out("Installing {$domain} certificate into {$webserver}");
        $this->out("  cert   : {$certFile}");
        $this->out("  key    : {$keyFile}");

        return match ($webserver) {
            'openresty' => $this->installOpenresty($domain, $certFile, $keyFile, $confPath),
            'nginx'     => $this->installNginx($domain, $certFile, $keyFile, $confPath),
            'apache', 'apache2' => $this->installApache($domain, $certFile, $keyFile, $confPath),
            default     => $this->unknownWebserver($webserver),
        };
    }

    // -------------------------------------------------------------------------
    // OpenResty
    // -------------------------------------------------------------------------

    private function installOpenresty(string $domain, string $certFile, string $keyFile, ?string $confPath): int
    {
        $confDir  = '/usr/local/openresty/nginx/conf/sites-available';
        $confFile = $confPath ?? "{$confDir}/{$domain}.conf";

        if (!file_exists($confFile)) {
            $this->fail("OpenResty vhost not found: {$confFile}");
            return 1;
        }

        $this->injectSslDirectives($confFile, $certFile, $keyFile);

        $this->out("Testing OpenResty configuration...");
        $testOut = [];
        exec('/usr/local/openresty/bin/openresty -t 2>&1', $testOut, $testCode);

        if ($testCode !== 0) {
            $this->fail("OpenResty config test failed:");
            foreach ($testOut as $line) { $this->err("  {$line}"); }
            return 1;
        }

        $this->success("OpenResty config test passed.");
        $this->out("Reloading OpenResty...");

        $this->serviceReload('openresty');
        $this->success("OpenResty reloaded with wildcard certificate.");
        $this->log('info', "certificate installed for {$domain} on openresty");
        return 0;
    }

    // -------------------------------------------------------------------------
    // Nginx
    // -------------------------------------------------------------------------

    private function installNginx(string $domain, string $certFile, string $keyFile, ?string $confPath): int
    {
        $confFile = $confPath ?? "/etc/nginx/sites-available/{$domain}.conf";

        if (!file_exists($confFile)) {
            $this->fail("Nginx vhost not found: {$confFile}");
            return 1;
        }

        $this->injectSslDirectives($confFile, $certFile, $keyFile);

        $testOut = [];
        exec('nginx -t 2>&1', $testOut, $testCode);

        if ($testCode !== 0) {
            $this->fail("Nginx config test failed:");
            foreach ($testOut as $line) { $this->err("  {$line}"); }
            return 1;
        }

        $this->success("Nginx config test passed.");
        $this->serviceReload('nginx');
        $this->success("Nginx reloaded with wildcard certificate.");
        $this->log('info', "certificate installed for {$domain} on nginx");
        return 0;
    }

    // -------------------------------------------------------------------------
    // Apache
    // -------------------------------------------------------------------------

    private function installApache(string $domain, string $certFile, string $keyFile, ?string $confPath): int
    {
        $confFile = $confPath ?? "/etc/apache2/sites-available/{$domain}-le-ssl.conf";

        // If an SSL vhost does not exist, we cannot install
        if (!file_exists($confFile)) {
            $this->fail("Apache SSL vhost not found: {$confFile}");
            $this->err("Create the vhost file and re-run, or use --conf to specify its path.");
            return 1;
        }

        // Apache: replace SSLCertificateFile and SSLCertificateKeyFile lines
        $conf = file_get_contents($confFile);
        $conf = preg_replace('/SSLCertificateFile\s+\S+/', "SSLCertificateFile {$certFile}", $conf);
        $conf = preg_replace('/SSLCertificateKeyFile\s+\S+/', "SSLCertificateKeyFile {$keyFile}", $conf);
        // fullchain includes intermediate, so we remove or set SSLCertificateChainFile
        $conf = preg_replace('/^\s*SSLCertificateChainFile\s+\S+/m', '', $conf);
        file_put_contents($confFile, $conf);

        $testOut = [];
        exec('apache2ctl configtest 2>&1', $testOut, $testCode);

        if ($testCode !== 0) {
            $this->fail("Apache config test failed:");
            foreach ($testOut as $line) { $this->err("  {$line}"); }
            return 1;
        }

        $this->success("Apache config test passed.");
        $this->serviceReload('apache2');
        $this->success("Apache reloaded with wildcard certificate.");
        $this->log('info', "certificate installed for {$domain} on apache");
        return 0;
    }

    // -------------------------------------------------------------------------
    // Shared helpers
    // -------------------------------------------------------------------------

    /**
     * Inject or update ssl_certificate / ssl_certificate_key into an nginx-style vhost.
     * Uses a safe awk replacement approach.
     */
    private function injectSslDirectives(string $confFile, string $certFile, string $keyFile): void
    {
        $conf = file_get_contents($confFile);

        // Normalize: strip the deprecated `http2` parameter from listen lines.
        // Newer nginx/OpenResty (≥1.25.1) requires `http2 on;` as a standalone
        // directive. Having both `listen 443 ssl http2;` and `http2 on;` causes
        // "http2 directive is duplicate" — a common state when the stored vhost
        // was written with old-style listen and the panel template re-added the
        // standalone directive.
        $conf = preg_replace('/\blisten(\s+\S+\s+ssl)\s+http2\s*;/i', 'listen$1;', $conf);

        // Already has directives → update in-place
        if (str_contains($conf, 'ssl_certificate ') || str_contains($conf, 'ssl_certificate_key ')) {
            $conf = preg_replace('/^\s*ssl_certificate\s+\S+;/m',           "    ssl_certificate {$certFile};", $conf);
            $conf = preg_replace('/^\s*ssl_certificate_key\s+\S+;/m',       "    ssl_certificate_key {$keyFile};", $conf);
            file_put_contents($confFile, $conf);
            $this->verbose("Updated existing SSL directives in {$confFile}");
            return;
        }

        // Inject after "# SSL certificates" marker, or before first location block
        $injected = "    listen 443 ssl;\n    ssl_certificate {$certFile};\n    ssl_certificate_key {$keyFile};\n";

        if (str_contains($conf, '# SSL certificates')) {
            $conf = preg_replace('/(# SSL certificates)/', $injected . '$1', $conf);
        } else {
            $conf = preg_replace('/(^\s*location\s)/m', $injected . '$1', $conf, 1);
        }

        file_put_contents($confFile, $conf);
        $this->verbose("Injected SSL directives into {$confFile}");
    }

    private function serviceReload(string $service): void
    {
        exec("systemctl is-active --quiet {$service}", $out, $active);
        $cmd = $active === 0 ? "service {$service} reload" : "service {$service} start";
        exec($cmd . ' 2>&1', $out, $code);
        if ($code !== 0) {
            $this->warn("{$service} reload returned exit code {$code}");
        }
    }

    private function unknownWebserver(string $webserver): int
    {
        $this->fail("Unknown webserver: {$webserver}. Supported: openresty, nginx, apache");
        return 1;
    }
}
