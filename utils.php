<?php
// backend/utils.php
require_once __DIR__ . "/config.php";

function json_out($data): string
{
    return json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
}

function random_token64(): string
{
    return bin2hex(random_bytes(32)); // 64 chars
}

function now_mysql(): string
{
    return date('Y-m-d H:i:s');
}

function mysql_add_days(int $days): string
{
    return date('Y-m-d H:i:s', time() + ($days * 86400));
}

function get_bearer_token(): ?string
{
    $headers = function_exists('apache_request_headers') ? apache_request_headers() : [];
    $auth = $headers['Authorization'] ?? $headers['authorization'] ?? ($_SERVER['HTTP_AUTHORIZATION'] ?? '');
    if (!$auth) return null;
    if (preg_match('/Bearer\s+(.+)/i', $auth, $m)) return trim($m[1]);
    return null;
}
