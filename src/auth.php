<?php
declare(strict_types=1);

function current_user(): ?array
{
    static $loaded = false;
    static $user = null;

    if ($loaded) {
        return $user;
    }

    $loaded = true;
    $userId = $_SESSION['user_id'] ?? null;
    if (!is_int($userId) || $userId < 1) {
        return null;
    }

    $statement = db()->prepare(
        'SELECT id, name, email, role, created_at, last_login_at FROM users WHERE id = :id LIMIT 1'
    );
    $statement->execute(['id' => $userId]);
    $row = $statement->fetch();

    if ($row === false) {
        unset($_SESSION['user_id'], $_SESSION['user_role'], $_SESSION['last_activity']);
        return null;
    }

    $user = $row;
    return $user;
}

function require_login(): void
{
    if (current_user() !== null) {
        return;
    }

    $requestUri = $_SERVER['REQUEST_URI'] ?? null;
    if (is_string($requestUri) && is_safe_intended_url($requestUri)) {
        $_SESSION['_intended_url'] = $requestUri;
    }

    if (!isset($_SESSION['_flash']['auth_notice'])) {
        flash('auth_notice', 'Please log in to continue.');
    }
    redirect('login.php');
}

function require_guest(): void
{
    if (current_user() !== null) {
        redirect('dashboard.php');
    }
}

function require_role(string $role): void
{
    require_login();

    if ((current_user()['role'] ?? null) !== $role) {
        http_response_code(403);
        $dashboardUrl = str_contains(dirname($_SERVER['SCRIPT_NAME'] ?? ''), '/admin')
            ? '../dashboard.php'
            : 'dashboard.php';
        $stylesheetUrl = str_contains(dirname($_SERVER['SCRIPT_NAME'] ?? ''), '/admin')
            ? '../assets/auth.css'
            : 'assets/auth.css';
        ?>
        <!doctype html>
        <html lang="en">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1">
            <title>Access denied</title>
            <link rel="stylesheet" href="<?= e($stylesheetUrl) ?>">
        </head>
        <body>
        <main class="auth-page">
            <section class="auth-card" aria-labelledby="page-title">
                <p class="eyebrow">403</p>
                <h1 id="page-title">Access denied</h1>
                <p class="intro">You do not have permission to view this page.</p>
                <p class="auth-link"><a href="<?= e($dashboardUrl) ?>">Return to your dashboard</a></p>
            </section>
        </main>
        </body>
        </html>
        <?php
        exit;
    }
}

function login_lockout_minutes(string $email, string $ip): ?int
{
    $statement = db()->prepare(
        'SELECT GREATEST(
            1,
            CEIL(TIMESTAMPDIFF(SECOND, CURRENT_TIMESTAMP, DATE_ADD(attempted_at, INTERVAL 15 MINUTE)) / 60)
        ) AS minutes_left
        FROM login_attempts
        WHERE email = :email
          AND ip = :ip
          AND attempted_at >= CURRENT_TIMESTAMP - INTERVAL 15 MINUTE
        ORDER BY attempted_at DESC
        LIMIT 5'
    );
    $statement->execute(['email' => $email, 'ip' => $ip]);
    $attempts = $statement->fetchAll();

    if (count($attempts) < 5) {
        return null;
    }

    return (int) $attempts[4]['minutes_left'];
}

function render_navbar(array $user, string $dashboardUrl, string $logoutUrl, string $adminUsersUrl): void
{
    ?>
    <header class="site-header">
        <nav class="site-nav" aria-label="Main navigation">
            <a class="brand-link" href="<?= e($dashboardUrl) ?>">SWD AUTH</a>
            <div class="nav-links">
                <?php if (($user['role'] ?? null) === 'admin'): ?>
                    <a href="<?= e($adminUsersUrl) ?>">Admin</a>
                <?php endif; ?>
                <form method="post" action="<?= e($logoutUrl) ?>">
                    <?= csrf_field() ?>
                    <button class="nav-button" type="submit">Log out</button>
                </form>
            </div>
        </nav>
    </header>
    <?php
}

function is_safe_intended_url(string $url): bool
{
    if (
        $url === ''
        || $url[0] !== '/'
        || str_starts_with($url, '//')
        || str_contains($url, '\\')
        || preg_match('/[\x00-\x20\x7f]/', $url) === 1
    ) {
        return false;
    }

    $parts = parse_url($url);

    return is_array($parts)
        && !isset($parts['scheme'])
        && !isset($parts['host'])
        && !isset($parts['user'])
        && !isset($parts['pass'])
        && isset($parts['path'])
        && str_starts_with($parts['path'], '/');
}

function auth_destroy_session(): void
{
    $_SESSION = [];

    $cookieParams = session_get_cookie_params();
    setcookie(session_name(), '', [
        'expires' => time() - 42000,
        'path' => $cookieParams['path'],
        'domain' => $cookieParams['domain'],
        'secure' => $cookieParams['secure'],
        'httponly' => $cookieParams['httponly'],
        'samesite' => $cookieParams['samesite'],
    ]);

    session_destroy();
}
