<?php
declare(strict_types=1);

require_once __DIR__ . '/bootstrap.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Allow: POST');
    http_response_code(405);
    exit('Method Not Allowed');
}

if (!csrf_verify()) {
    http_response_code(403);
    exit('Invalid CSRF token');
}

auth_destroy_session();
session_id('');
session_start();
flash('auth_notice', 'You have been logged out.');
session_write_close();

redirect('login.php');
