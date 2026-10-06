<?php
require __DIR__ . '/draft.php';

$draft = null;
$error = '';
try {
    $draft = load_draft();
} catch (Throwable $e) {
    $error = get_class($e) . ': ' . $e->getMessage();
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $fresh              = new DraftMessage();
    $fresh->subject     = (string) ($_POST['subject'] ?? '');
    $fresh->body        = (string) ($_POST['body'] ?? '');
    $fresh->attachments = [];
    setcookie('draft', base64_encode(serialize($fresh)), 0, '/');
    header('Location: index.php');
    exit;
}
?>
<!doctype html><meta charset="utf-8"><title>postbox</title>
<style>
 body{font:14px/1.5 ui-monospace,monospace;max-width:52rem;margin:2rem auto;padding:0 1rem}
 input,textarea{width:100%;font:inherit} pre{background:#f4f4f4;padding:.6rem;overflow:auto;
 white-space:pre-wrap;word-break:break-all} fieldset{border:1px solid #bbb} .e{color:#900}
</style>
<h1>postbox</h1>
<p>Drafts are kept in your browser. &middot; <a href="spool.php">outbox spool</a></p>
<?php if ($error): ?><p class="e"><?= htmlspecialchars($error) ?></p><?php endif; ?>

<form method="post">
 <fieldset><legend>Compose</legend>
  <label>Subject <input name="subject" value="<?= htmlspecialchars(is_string($draft->subject ?? null) ? $draft->subject : '') ?>"></label>
  <label>Body<br><textarea name="body" rows="6"><?= htmlspecialchars(is_string($draft->body ?? null) ? $draft->body : '') ?></textarea></label>
  <p><button>Save draft</button></p>
 </fieldset>
</form>

<h2>Restored draft</h2>
<pre><?= htmlspecialchars($draft === null ? '(no draft cookie)' : print_r($draft, true)) ?></pre>
