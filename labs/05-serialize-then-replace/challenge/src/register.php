<?php
require __DIR__ . '/lib.php';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    header('Location: index.php');
    exit;
}

$username = isset($_POST['username']) ? $_POST['username'] : '';
$password = isset($_POST['password']) ? $_POST['password'] : '';

if (!valid_username($username)) {
    page('error', '<p>usernames are 3-32 chars of [A-Za-z0-9_].</p>');
    exit;
}
if (!is_string($password) || strlen($password) < 1) {
    page('error', '<p>a password is required.</p>');
    exit;
}
if (is_file(profile_file($username))) {
    page('error', '<p>that username is taken.</p>');
    exit;
}

file_put_contents(STORE . '/pw/' . $username, password_hash($password, PASSWORD_DEFAULT));
save_profile(new Profile('newcomer', $username, 'nothing here yet'));
start_session($username);

header('Location: profile.php');
