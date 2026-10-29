<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

require_login();
$user = current_user();
if ($user === null) {
    throw new RuntimeException('Authenticated user could not be loaded.');
}

$notice = flash('auth_notice');
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Dashboard</title>
    <link rel="stylesheet" href="assets/auth.css">
</head>
<body>
<main class="auth-page">
    <section class="auth-card" aria-labelledby="page-title">
        <p class="eyebrow">SWD AUTH</p>
        <h1 id="page-title">Welcome, <?= e((string) $user['name']) ?></h1>
        <p class="intro">You are logged in to your account.</p>

        <?php if ($notice !== null): ?>
            <div class="notice" role="status"><?= e($notice) ?></div>
        <?php endif; ?>

        <dl class="account-details">
            <div>
                <dt>Email</dt>
                <dd><?= e((string) $user['email']) ?></dd>
            </div>
            <div>
                <dt>Role</dt>
                <dd><?= e((string) $user['role']) ?></dd>
            </div>
            <div>
                <dt>Member since</dt>
                <dd><?= e((string) $user['created_at']) ?></dd>
            </div>
            <div>
                <dt>Last login</dt>
                <dd><?= e((string) ($user['last_login_at'] ?? 'Not available')) ?></dd>
            </div>
        </dl>

        <form method="post" action="logout.php">
            <?= csrf_field() ?>
            <button type="submit">Log out</button>
        </form>
    </section>
</main>
</body>
</html>
