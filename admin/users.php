<?php
declare(strict_types=1);

require_once __DIR__ . '/../bootstrap.php';

require_role('admin');
$user = current_user();
if ($user === null) {
    throw new RuntimeException('Authenticated user could not be loaded.');
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (!csrf_verify()) {
        http_response_code(403);
        flash('users_error', 'Your form session expired. Please try again.');
        redirect('users.php');
    }

    $targetId = filter_var($_POST['user_id'] ?? null, FILTER_VALIDATE_INT);
    $newRole = $_POST['role'] ?? null;

    if (!is_int($targetId) || $targetId < 1 || !in_array($newRole, ['user', 'admin'], true)) {
        flash('users_error', 'Choose a valid user and role.');
        redirect('users.php');
    }

    if ($targetId === (int) $user['id'] && $newRole !== 'admin') {
        flash('users_error', 'You cannot remove your own admin role.');
        redirect('users.php');
    }

    $statement = db()->prepare('SELECT id FROM users WHERE id = :id LIMIT 1');
    $statement->execute(['id' => $targetId]);
    if ($statement->fetch() === false) {
        flash('users_error', 'That user could not be found.');
        redirect('users.php');
    }

    $statement = db()->prepare('UPDATE users SET role = :role WHERE id = :id');
    $statement->execute(['role' => $newRole, 'id' => $targetId]);
    flash('users_notice', 'User role updated.');
    redirect('users.php');
}

$statement = db()->query(
    'SELECT id, name, email, role, created_at, last_login_at FROM users ORDER BY id ASC'
);
$users = $statement->fetchAll();
$error = flash('users_error');
$notice = flash('users_notice');
?>
<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Manage users</title>
    <link rel="stylesheet" href="../assets/auth.css">
</head>
<body>
<?php render_navbar($user, '../dashboard.php', '../logout.php', 'users.php'); ?>
<main class="auth-page">
    <section class="auth-card auth-card-wide" aria-labelledby="page-title">
        <p class="eyebrow">ADMIN</p>
        <h1 id="page-title">Manage users</h1>
        <p class="intro">Review accounts and update their roles.</p>

        <?php if ($notice !== null): ?>
            <div class="notice" role="status"><?= e($notice) ?></div>
        <?php endif; ?>
        <?php if ($error !== null): ?>
            <div class="alert" role="alert"><?= e($error) ?></div>
        <?php endif; ?>

        <div class="table-wrap">
            <table class="users-table">
                <thead>
                <tr>
                    <th scope="col">Name</th>
                    <th scope="col">Email</th>
                    <th scope="col">Role</th>
                    <th scope="col">Created</th>
                    <th scope="col">Last login</th>
                    <th scope="col">Update role</th>
                </tr>
                </thead>
                <tbody>
                <?php foreach ($users as $listedUser): ?>
                    <tr>
                        <td><?= e((string) $listedUser['name']) ?></td>
                        <td><?= e((string) $listedUser['email']) ?></td>
                        <td><?= e((string) $listedUser['role']) ?></td>
                        <td><?= e((string) $listedUser['created_at']) ?></td>
                        <td><?= e((string) ($listedUser['last_login_at'] ?? 'Never')) ?></td>
                        <td>
                            <form method="post" action="users.php">
                                <?= csrf_field() ?>
                                <input type="hidden" name="user_id" value="<?= (int) $listedUser['id'] ?>">
                                <label class="visually-hidden" for="role-<?= (int) $listedUser['id'] ?>">
                                    Role for <?= e((string) $listedUser['name']) ?>
                                </label>
                                <select id="role-<?= (int) $listedUser['id'] ?>" name="role">
                                    <option value="user"<?= $listedUser['role'] === 'user' ? ' selected' : '' ?>>User</option>
                                    <option value="admin"<?= $listedUser['role'] === 'admin' ? ' selected' : '' ?>>Admin</option>
                                </select>
                                <button type="submit">Save</button>
                            </form>
                        </td>
                    </tr>
                <?php endforeach; ?>
                </tbody>
            </table>
        </div>
    </section>
</main>
</body>
</html>
