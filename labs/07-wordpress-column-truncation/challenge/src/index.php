<?php
session_start();
require __DIR__ . '/meta.php';
require __DIR__ . '/gadgets.php';

$uid    = current_user();
$notice = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    update_user_meta($uid, 'bio', (string) ($_POST['bio'] ?? ''));
    update_user_meta($uid, 'prefs', [
        'theme' => (string) ($_POST['theme'] ?? 'light'),
        'lang'  => (string) ($_POST['lang'] ?? 'en'),
    ]);
    $notice = 'Profile saved.';
}

$bio   = get_user_meta($uid, 'bio');
$prefs = get_user_meta($uid, 'prefs');
?>
<!doctype html><meta charset="utf-8"><title>inkpress &mdash; profile</title>
<style>
 body{font:14px/1.5 ui-monospace,monospace;max-width:52rem;margin:2rem auto;padding:0 1rem}
 textarea,input{width:100%;font:inherit} pre{background:#f4f4f4;padding:.6rem;overflow:auto}
 fieldset{border:1px solid #bbb} .n{color:#070}
</style>
<h1>inkpress</h1>
<p>Signed in as <b><?= htmlspecialchars($_SESSION['login']) ?></b> (user #<?= $uid ?>).
   &middot; <a href="activity.php">activity log</a></p>
<?php if ($notice): ?><p class="n"><?= htmlspecialchars($notice) ?></p><?php endif; ?>

<form method="post">
 <fieldset><legend>Edit profile</legend>
  <label>Bio<br><textarea name="bio" rows="5"><?= htmlspecialchars(is_string($bio) ? $bio : '') ?></textarea></label>
  <label>Theme <input name="theme" value="<?= htmlspecialchars($prefs['theme'] ?? 'light') ?>"></label>
  <label>Language <input name="lang" value="<?= htmlspecialchars($prefs['lang'] ?? 'en') ?>"></label>
  <p><button>Save</button></p>
 </fieldset>
</form>

<h2>Stored metadata (as returned by get_user_meta)</h2>
<pre><?= htmlspecialchars(print_r(['bio' => $bio, 'prefs' => $prefs], true)) ?></pre>
