<?php
declare(strict_types=1);

$showErrors = getenv('APP_ENV') === 'development';
error_reporting(E_ALL);
ini_set('display_errors', $showErrors ? '1' : '0');
ini_set('display_startup_errors', $showErrors ? '1' : '0');

header('X-Frame-Options: DENY');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: strict-origin-when-cross-origin');

require_once __DIR__ . '/config/db.php';
require_once __DIR__ . '/src/helpers.php';
require_once __DIR__ . '/src/csrf.php';
require_once __DIR__ . '/src/auth.php';

ini_set('session.use_strict_mode', '1');
ini_set('session.use_only_cookies', '1');
ini_set('session.use_trans_sid', '0');

$isHttps = isset($_SERVER['HTTPS']) && strtolower((string) $_SERVER['HTTPS']) !== 'off';

session_name('SWDSESSID');
session_set_cookie_params([
    'lifetime' => 0,
    'path' => '/',
    'secure' => $isHttps,
    'httponly' => true,
    'samesite' => 'Lax',
]);
session_start();

if (isset($_SESSION['user_id'])) {
    $lastActivity = $_SESSION['last_activity'] ?? null;

    if (!is_int($lastActivity) || $lastActivity <= time() - 1800) {
        auth_destroy_session();
        session_id('');
        session_start();
        flash('auth_notice', 'You were signed out after 30 minutes of inactivity.');
    } else {
        $_SESSION['last_activity'] = time();
    }
}
