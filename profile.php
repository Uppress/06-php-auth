<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

require_login();
$user = current_user();
if ($user === null) {
    throw new RuntimeException('Authenticated user could not be loaded.');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_verify()) {
        http_response_code(403);
        exit('Invalid CSRF token');
    }

    $action = $_POST['action'] ?? null;

    if ($action === 'update_profile') {
        $name = is_string($_POST['name'] ?? null) ? trim($_POST['name']) : '';
        $email = is_string($_POST['email'] ?? null) ? strtolower(trim($_POST['email'])) : '';
        $_SESSION['_old_profile'] = ['name' => $name, 'email' => $email];
        $errors = [];

        $nameLength = preg_match_all('/./us', $name);
        if ($nameLength === false || $nameLength < 1 || $nameLength > 100) {
            $errors[] = 'Enter a name between 1 and 100 characters.';
        }

        $emailLength = preg_match_all('/./us', $email);
        if ($emailLength === false || $emailLength > 160 || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            $errors[] = 'Enter a valid email address (maximum 160 characters).';
        }

        if ($errors === []) {
            $statement = db()->prepare('SELECT id FROM users WHERE email = :email AND id <> :id LIMIT 1');
            $statement->execute(['email' => $email, 'id' => (int) $user['id']]);
            if ($statement->fetch() !== false) {
                $errors[] = 'An account with that email address already exists.';
            }
        }

        if ($errors !== []) {
            flash('profile_error', implode(' ', $errors));
            redirect('profile.php');
        }

        try {
            $statement = db()->prepare('UPDATE users SET name = :name, email = :email WHERE id = :id');
            $statement->execute([
                'name' => $name,
                'email' => $email,
                'id' => (int) $user['id'],
            ]);
        } catch (PDOException $exception) {
            $isDuplicateEmail = $exception->getCode() === '23000'
                && isset($exception->errorInfo[1])
                && (int) $exception->errorInfo[1] === 1062;

            if (!$isDuplicateEmail) {
                throw $exception;
            }

            flash('profile_error', 'An account with that email address already exists.');
            redirect('profile.php');
        }

        unset($_SESSION['_old_profile']);
        flash('profile_notice', 'Your profile has been updated.');
        redirect('profile.php');
    }

    if ($action === 'change_password') {
        $currentPassword = $_POST['current_password'] ?? null;
        $newPassword = $_POST['new_password'] ?? null;
        $confirmPassword = $_POST['confirm_password'] ?? null;
        $errors = [];
        $statement = db()->prepare('SELECT password_hash FROM users WHERE id = :id LIMIT 1');
        $statement->execute(['id' => (int) $user['id']]);
        $passwordRow = $statement->fetch();

        if (
            $passwordRow === false
            || !is_string($currentPassword)
            || !password_verify($currentPassword, (string) $passwordRow['password_hash'])
        ) {
            $errors[] = 'Your current password is incorrect.';
        }

        if (!is_string($newPassword) || !is_string($confirmPassword)) {
            $errors[] = 'Enter and confirm your new password.';
        } else {
            $passwordLength = preg_match_all('/./us', $newPassword);
            if (
                $passwordLength === false
                || $passwordLength < 10
                || preg_match('/\p{L}/u', $newPassword) !== 1
                || preg_match('/\p{N}/u', $newPassword) !== 1
            ) {
                $errors[] = 'Your new password must be at least 10 characters and include a letter and a number.';
            } elseif (PASSWORD_DEFAULT === PASSWORD_BCRYPT && strlen($newPassword) > 72) {
                $errors[] = 'Your new password must be no more than 72 bytes.';
            }

            if ($newPassword !== $confirmPassword) {
                $errors[] = 'The new passwords do not match.';
            }
        }

        if ($errors !== []) {
            flash('profile_error', implode(' ', $errors));
            redirect('profile.php');
        }

        $passwordHash = password_hash($newPassword, PASSWORD_DEFAULT);
        if (!is_string($passwordHash)) {
            throw new RuntimeException('Unable to hash the new password.');
        }

        $statement = db()->prepare('UPDATE users SET password_hash = :password_hash WHERE id = :id');
        $statement->execute([
            'password_hash' => $passwordHash,
            'id' => (int) $user['id'],
        ]);

        session_regenerate_id(true);
        unset($_SESSION['_csrf_token']);
        $_SESSION['last_activity'] = time();
        flash('profile_notice', 'Your password has been changed.');
        redirect('profile.php');
    }

    flash('profile_error', 'Choose a valid profile action.');
    redirect('profile.php');
}

$error = flash('profile_error');
$notice = flash('profile_notice');
$oldProfile = $_SESSION['_old_profile'] ?? [];
$name = is_array($oldProfile) && is_string($oldProfile['name'] ?? null)
    ? $oldProfile['name']
    : (string) $user['name'];
$email = is_array($oldProfile) && is_string($oldProfile['email'] ?? null)
    ? $oldProfile['email']
    : (string) $user['email'];
unset($_SESSION['_old_profile']);
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Your profile</title>
    <link rel="stylesheet" href="assets/auth.css">
</head>
<body>
<?php render_navbar($user, 'dashboard.php', 'logout.php', 'admin/users.php', 'profile.php'); ?>
<main class="auth-page">
    <section class="auth-card" aria-labelledby="page-title">
        <p class="eyebrow">ACCOUNT</p>
        <h1 id="page-title">Your profile</h1>
        <p class="intro">Update your account details and password.</p>

        <?php if ($notice !== null): ?>
            <div class="notice" role="status"><?= e($notice) ?></div>
        <?php endif; ?>
        <?php if ($error !== null): ?>
            <div class="alert" role="alert"><?= e($error) ?></div>
        <?php endif; ?>

        <section class="form-section" aria-labelledby="details-title">
            <h2 id="details-title">Profile details</h2>
            <form method="post" action="profile.php">
                <?= csrf_field() ?>
                <input type="hidden" name="action" value="update_profile">
                <label for="name">Name</label>
                <input id="name" name="name" type="text" maxlength="100" autocomplete="name" required
                       value="<?= e($name) ?>">

                <label for="email">Email address</label>
                <input id="email" name="email" type="email" maxlength="160" autocomplete="email" required
                       value="<?= e($email) ?>">

                <button type="submit">Save profile</button>
            </form>
        </section>

        <section class="form-section" aria-labelledby="password-title">
            <h2 id="password-title">Change password</h2>
            <form method="post" action="profile.php">
                <?= csrf_field() ?>
                <input type="hidden" name="action" value="change_password">
                <label for="current_password">Current password</label>
                <input id="current_password" name="current_password" type="password"
                       autocomplete="current-password" required>

                <label for="new_password">New password</label>
                <input id="new_password" name="new_password" type="password" autocomplete="new-password"
                       minlength="10" required>
                <p class="field-help">At least 10 characters, including a letter and a number.</p>

                <label for="confirm_password">Confirm new password</label>
                <input id="confirm_password" name="confirm_password" type="password"
                       autocomplete="new-password" minlength="10" required>

                <button type="submit">Change password</button>
            </form>
        </section>
    </section>
</main>
</body>
</html>
