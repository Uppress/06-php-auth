<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

if (isset($_SESSION['user_id'])) {
    redirect('dashboard.php');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_verify()) {
        http_response_code(403);
        flash('register_error', 'Your form session expired. Please try again.');
    } else {
        $_SESSION['_old'] = [
            'name' => is_string($_POST['name'] ?? null) ? trim($_POST['name']) : '',
            'email' => is_string($_POST['email'] ?? null) ? trim($_POST['email']) : '',
        ];

        $name = $_SESSION['_old']['name'];
        $email = strtolower($_SESSION['_old']['email']);
        $password = $_POST['password'] ?? null;
        $confirmPassword = $_POST['confirm_password'] ?? null;
        $errors = [];

        $nameLength = preg_match_all('/./us', $name);
        if ($nameLength === false || $nameLength < 1 || $nameLength > 100) {
            $errors[] = 'Enter a name between 1 and 100 characters.';
        }

        $emailLength = preg_match_all('/./us', $email);
        if ($emailLength === false || $emailLength > 160 || filter_var($email, FILTER_VALIDATE_EMAIL) === false) {
            $errors[] = 'Enter a valid email address (maximum 160 characters).';
        }

        if (!is_string($password) || !is_string($confirmPassword)) {
            $errors[] = 'Enter and confirm your password.';
        } else {
            $passwordLength = preg_match_all('/./us', $password);
            if (
                $passwordLength === false
                || $passwordLength < 10
                || preg_match('/\p{L}/u', $password) !== 1
                || preg_match('/\p{N}/u', $password) !== 1
            ) {
                $errors[] = 'Your password must be at least 10 characters and include a letter and a number.';
            } elseif (PASSWORD_DEFAULT === PASSWORD_BCRYPT && strlen($password) > 72) {
                $errors[] = 'Your password must be no more than 72 bytes.';
            }

            if ($password !== $confirmPassword) {
                $errors[] = 'The passwords do not match.';
            }
        }

        if ($errors === []) {
            $connection = db();
            $statement = $connection->prepare('SELECT id FROM users WHERE email = :email LIMIT 1');
            $statement->execute(['email' => $email]);

            if ($statement->fetch() !== false) {
                $errors[] = 'An account with that email address already exists.';
            }
        }

        if ($errors !== []) {
            flash('register_error', implode(' ', $errors));
            redirect('register.php');
        }

        $passwordHash = password_hash($password, PASSWORD_DEFAULT);

        try {
            $statement = $connection->prepare(
                'INSERT INTO users (name, email, password_hash) VALUES (:name, :email, :password_hash)'
            );
            $statement->execute([
                'name' => $name,
                'email' => $email,
                'password_hash' => $passwordHash,
            ]);
        } catch (PDOException $exception) {
            $isDuplicateEmail = $exception->getCode() === '23000'
                && isset($exception->errorInfo[1])
                && (int) $exception->errorInfo[1] === 1062;

            if (!$isDuplicateEmail) {
                throw $exception;
            }

            flash('register_error', 'An account with that email address already exists.');
            redirect('register.php');
        }

        session_regenerate_id(true);
        unset($_SESSION['_csrf_token'], $_SESSION['_old']);
        $_SESSION['user_id'] = (int) $connection->lastInsertId();
        $_SESSION['user_name'] = $name;
        $_SESSION['user_role'] = 'user';
        $_SESSION['last_activity'] = time();

        redirect('dashboard.php');
    }
}

$error = flash('register_error');
$name = old('name');
$email = old('email');
unset($_SESSION['_old']);
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Create account</title>
    <link rel="stylesheet" href="assets/auth.css">
</head>
<body>
<main class="auth-page">
    <section class="auth-card" aria-labelledby="page-title">
        <p class="eyebrow">SWD AUTH</p>
        <h1 id="page-title">Create your account</h1>
        <p class="intro">Get started by filling in your details below.</p>

        <?php if ($error !== null): ?>
            <div class="alert" role="alert"><?= e($error) ?></div>
        <?php endif; ?>

        <form method="post" action="register.php">
            <?= csrf_field() ?>
            <label for="name">Name</label>
            <input id="name" name="name" type="text" maxlength="100" autocomplete="name" required
                   value="<?= e($name) ?>">

            <label for="email">Email address</label>
            <input id="email" name="email" type="email" maxlength="160" autocomplete="email" required
                   value="<?= e($email) ?>">

            <label for="password">Password</label>
            <input id="password" name="password" type="password" autocomplete="new-password"
                   minlength="10" required>
            <p class="field-help">At least 10 characters, including a letter and a number.</p>

            <label for="confirm_password">Confirm password</label>
            <input id="confirm_password" name="confirm_password" type="password"
                   autocomplete="new-password" minlength="10" required>

            <button type="submit">Create account</button>
        </form>
        <p class="auth-link">Already have an account? <a href="login.php">Log in</a></p>
    </section>
</main>
</body>
</html>
