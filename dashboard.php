<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

if (!isset($_SESSION['user_id'], $_SESSION['user_name'])) {
    flash('register_error', 'Please create an account to continue.');
    redirect('register.php');
}
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
        <h1 id="page-title">Welcome, <?= e((string) $_SESSION['user_name']) ?></h1>
        <p class="intro">Your account is ready.</p>
    </section>
</main>
</body>
</html>
