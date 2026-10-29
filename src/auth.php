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
        echo 'Forbidden';
        exit;
    }
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
