# SWD PHP Authentication

A PHP 8 and MySQL authentication example for XAMPP. It expects a MySQL database
named `swd_auth` with the `users` and `login_attempts` tables.

## Run locally

1. Start MySQL in the XAMPP Control Panel and create the database/tables:

   ```sql
   CREATE DATABASE IF NOT EXISTS swd_auth
       CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
   USE swd_auth;

   CREATE TABLE users (
       id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
       name VARCHAR(100) NOT NULL,
       email VARCHAR(160) NOT NULL UNIQUE,
       password_hash VARCHAR(255) NOT NULL,
       role ENUM('user', 'admin') NOT NULL DEFAULT 'user',
       created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
       last_login_at DATETIME NULL
   ) ENGINE=InnoDB;

   CREATE TABLE login_attempts (
       id INT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
       email VARCHAR(160) NOT NULL,
       ip VARCHAR(45) NOT NULL,
       attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
       INDEX (email, attempted_at)
   ) ENGINE=InnoDB;
   ```
2. The default database connection is `127.0.0.1:3306`, database `swd_auth`,
   user `root`, and an empty password. Override these defaults with
   `SWD_DB_HOST`, `SWD_DB_PORT`, `SWD_DB_NAME`, `SWD_DB_USER`, and `SWD_DB_PASS`
   environment variables.
3. Enable local development errors and start the PHP development server from
   this folder:

   ```powershell
   $env:APP_ENV = 'development'
   C:\xampp\php\php.exe -S 127.0.0.1:8001 -t C:\xampp\htdocs\swd\06-php-auth
   ```

4. Open <http://127.0.0.1:8001/register.php> to create an account.

Use a dedicated MySQL account with only the required database privileges outside
of a disposable local development environment.

## Promote the first admin

After registering the account, run this from a terminal:

```powershell
C:\xampp\php\php.exe C:\xampp\htdocs\swd\06-php-auth\promote-admin.php me@example.com
```

The script is CLI-only. Admins can manage roles at `/admin/users.php`.

## Security features

- Passwords are stored with PHP's `password_hash()` using `PASSWORD_DEFAULT`;
  login verifies them using `password_verify()` and upgrades outdated hashes.
- PDO uses prepared statements, exception error handling, and native prepares.
- Sessions use a custom cookie name, strict mode, HTTP-only and SameSite=Lax
  cookies, HTTPS-only cookies when served over HTTPS, and regenerate the ID at
  authentication and password-change boundaries.
- Authenticated sessions expire after 30 minutes without activity.
- Forms use session-bound CSRF tokens. Logout and role changes require POST.
- Login errors are generic. Failed attempts are tracked per email and client IP;
  five failures in 15 minutes temporarily block that pair.
- Authenticated pages enforce login and role checks. Intended post-login URLs
  must be relative paths, preventing external open redirects.
- Output is HTML-escaped. Responses set `X-Frame-Options`,
  `X-Content-Type-Options`, and `Referrer-Policy`.
- Profile updates validate fields and enforce the database's unique email
  constraint. Password changes require the current password and the new
  password is never repopulated into the form.

## Production deployment

Error display is disabled unless `APP_ENV=development` is explicitly set. Keep
it unset in production and log errors privately instead. Use HTTPS, a strong
database credential, and a production web server configuration. The built-in
PHP server is for development only.
