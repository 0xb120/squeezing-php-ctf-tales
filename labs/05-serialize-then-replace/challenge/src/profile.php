<?php
require __DIR__ . '/lib.php';

$user = current_user();
if ($user === null) {
    header('Location: index.php');
    exit;
}

$msg = '';
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $nickname = isset($_POST['nickname']) ? (string) $_POST['nickname'] : '';
    $bio      = isset($_POST['bio'])      ? (string) $_POST['bio']      : '';

    if (strlen($nickname) > 255) {
        $msg = '<p>nickname is too long (255 max).</p>';
    } elseif (strlen($bio) > 512) {
        $msg = '<p>bio is too long (512 max).</p>';
    } else {
        save_profile(new Profile($nickname, $user, $bio));
        $msg = '<p>profile saved.</p>';
    }
}

$p = load_profile($user);

$nickname = ($p instanceof Profile) ? $p->nickname : '';
$bio      = ($p instanceof Profile) ? $p->bio      : '';

page('profile', $msg . '
<p><img src="avatar.php" width="48" height="48" alt="avatar"> signed in as <b>' . e($user) . '</b></p>
<pre>nickname: ' . e($nickname) . '
bio     : ' . e($bio) . '</pre>
<form method="post">
  <fieldset><legend>edit profile</legend>
    <label>nickname <input name="nickname" value="" autocomplete="off"></label>
    <label>bio <textarea name="bio" rows="4"></textarea></label>
    <p><button>save</button></p>
  </fieldset>
</form>');
