<?php

namespace App\Services;

use Psr\Log\LoggerInterface;

class Analytics
{
    public function __construct(
        private readonly bool $trackingEnabled,
        private readonly LoggerInterface $logger
    )
    {
    }

    /**
     * #VULNERABILITY: Intended vulnerable request (SSRF + RCE in the referer header)
     */
    public function track(): void {
        if (!$this->trackingEnabled) {
            return;
        }

        // Get the referer header
        $referer = $_SERVER['HTTP_REFERER'] ?? null;
        if (!$referer || !$this->validate($referer)) {
            return;
        }

        // Request the URL through the cURL extension to retrieve only the HTTP
        // status code. Using the cURL API instead of passing the referer to a
        // shell removes the command injection (RCE); validate() restricts the
        // target to public HTTP(S) hosts to prevent SSRF.
        $ch = curl_init($referer);
        curl_setopt($ch, CURLOPT_NOBODY, true);
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, false);
        curl_setopt($ch, CURLOPT_CONNECTTIMEOUT, 5);
        curl_setopt($ch, CURLOPT_TIMEOUT, 5);
        curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
        curl_exec($ch);
        $statusCode = curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        curl_close($ch);

        // Log the response status
        $this->logger->info('Referer URL response status: ' . $statusCode);
    }

    public function validate(string $url): bool
    {
        if (filter_var($url, FILTER_VALIDATE_URL) === false) {
            return false;
        }

        // Only allow HTTP(S) URLs
        $scheme = strtolower((string) parse_url($url, PHP_URL_SCHEME));
        if (!in_array($scheme, ['http', 'https'], true)) {
            return false;
        }

        // Make sure the host does not resolve to a private, reserved or
        // loopback address, which would allow SSRF against internal services.
        $host = parse_url($url, PHP_URL_HOST);
        if (!$host) {
            return false;
        }

        $ips = [];
        if (filter_var($host, FILTER_VALIDATE_IP)) {
            $ips[] = $host;
        } else {
            foreach (array_merge(dns_get_record($host, DNS_A) ?: [], dns_get_record($host, DNS_AAAA) ?: []) as $record) {
                $ips[] = $record['ip'] ?? $record['ipv6'] ?? null;
            }
        }

        $ips = array_filter($ips);
        if (empty($ips)) {
            return false;
        }

        foreach ($ips as $ip) {
            if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false) {
                return false;
            }
        }

        return true;
    }
}