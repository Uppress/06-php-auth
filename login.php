<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

require_guest();

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_verify()) {
        http_response_code(403);
        flash('login_error', 'Your form session expired. Please try again.');
    } else {
        $email = is_string($_POST['email'] ?? null) ? strtolower(trim($_POST['email'])) : '';
        $password = $_POST['password'] ?? null;
        $_SESSION['_old_email'] = $email;
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';

        if (!is_string($ip) || filter_var($ip, FILTER_VALIDATE_IP) === false) {
            throw new RuntimeException('A valid client IP address is required for login throttling.');
        }

        $attemptEmail = strlen($email) <= 160
            ? $email
            : substr($email, 0, 95) . '#' . hash('sha256', $email);
        $lockout = login_lockout_minutes($attemptEmail, $ip);

        if ($lockout !== null) {
            flash('login_error', 'Too many attempts, try again in ' . $lockout . ' minutes');
            redirect('login.php');
        }

        if (is_string($password) && strlen($email) <= 160) {
            $statement = db()->prepare(
                'SELECT id, password_hash, role FROM users WHERE email = :email LIMIT 1'
            );
            $statement->execute(['email' => $email]);
            $user = $statement->fetch();
        } else {
            $user = false;
        }

        if (
            $user === false
            || !is_string($password)
            || !password_verify($password, (string) $user['password_hash'])
        ) {
            $statement = db()->prepare('INSERT INTO login_attempts (email, ip) VALUES (:email, :ip)');
            $statement->execute(['email' => $attemptEmail, 'ip' => $ip]);

            $lockout = login_lockout_minutes($attemptEmail, $ip);
            flash(
                'login_error',
                $lockout === null
                    ? 'Invalid email or password'
                    : 'Too many attempts, try again in ' . $lockout . ' minutes'
            );
            redirect('login.php');
        }

        $statement = db()->prepare('DELETE FROM login_attempts WHERE email = :email AND ip = :ip');
        $statement->execute(['email' => $attemptEmail, 'ip' => $ip]);

        $newPasswordHash = null;
        if (password_needs_rehash((string) $user['password_hash'], PASSWORD_DEFAULT)) {
            $newPasswordHash = password_hash($password, PASSWORD_DEFAULT);
            if (!is_string($newPasswordHash)) {
                throw new RuntimeException('Unable to re-hash the password.');
            }
        }

        if ($newPasswordHash === null) {
            $statement = db()->prepare('UPDATE users SET last_login_at = CURRENT_TIMESTAMP WHERE id = :id');
            $statement->execute(['id' => (int) $user['id']]);
        } else {
            $statement = db()->prepare(
                'UPDATE users SET password_hash = :password_hash, last_login_at = CURRENT_TIMESTAMP WHERE id = :id'
            );
            $statement->execute([
                'password_hash' => $newPasswordHash,
                'id' => (int) $user['id'],
            ]);
        }

        $intendedUrl = $_SESSION['_intended_url'] ?? null;
        unset($_SESSION['_intended_url'], $_SESSION['_old_email'], $_SESSION['_csrf_token']);
        session_regenerate_id(true);
        $_SESSION['user_id'] = (int) $user['id'];
        $_SESSION['user_role'] = (string) $user['role'];
        $_SESSION['last_activity'] = time();

        redirect(
            is_string($intendedUrl) && is_safe_intended_url($intendedUrl)
                ? $intendedUrl
                : 'dashboard.php'
        );
    }
}

$error = flash('login_error');
$notice = flash('auth_notice');
$email = $_SESSION['_old_email'] ?? '';
$email = is_string($email) ? $email : '';
unset($_SESSION['_old_email']);
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Log in</title>
    <link rel="stylesheet" href="assets/auth.css">
</head>
<body>
<main class="auth-page">
    <section class="auth-card" aria-labelledby="page-title">
        <p class="eyebrow">SWD AUTH</p>
        <h1 id="page-title">Welcome back</h1>
        <p class="intro">Log in to continue to your account.</p>

        <?php if ($notice !== null): ?>
            <div class="notice" role="status"><?= e($notice) ?></div>
        <?php endif; ?>
        <?php if ($error !== null): ?>
            <div class="alert" role="alert"><?= e($error) ?></div>
        <?php endif; ?>

        <form method="post" action="login.php">
            <?= csrf_field() ?>
            <label for="email">Email address</label>
            <input id="email" name="email" type="email" maxlength="160" autocomplete="email" required
                   value="<?= e($email) ?>">

            <label for="password">Password</label>
            <input id="password" name="password" type="password" autocomplete="current-password" required>

            <button type="submit">Log in</button>
        </form>

        <p class="field-help">For your security, we do not reveal whether the email or password was incorrect.</p>
        <p class="auth-link">Don't have an account? <a href="register.php">Create one</a></p>
    </section>
</main>
</body>
</html>
