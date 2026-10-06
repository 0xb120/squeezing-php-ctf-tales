<?php
/**
 * Nimbus Panel - "Remote database health check".
 *
 * An operator types the credentials of one of our customer databases and we
 * connect to it to make sure it is alive and to record its version.
 *
 * LOCAL INFILE is switched on because the nightly importer uses
 * `LOAD DATA LOCAL INFILE` against the same connection settings.
 */
require __DIR__ . '/lib.php';

$log    = new DebugLogger();
$result = null;
$error  = null;
$notice = null;

$host = $_POST['host'] ?? 'db.internal';
$port = $_POST['port'] ?? '3306';
$user = $_POST['user'] ?? 'healthcheck';
$pass = $_POST['pass'] ?? '';
$name = $_POST['dbname'] ?? 'nimbus';

if (($_POST['action'] ?? '') === 'dbtest') {
    $log->write("health check against {$host}:{$port} as {$user}");

    $mysqli = mysqli_init();
    // The importer needs LOAD DATA LOCAL INFILE, so keep it enabled.
    mysqli_options($mysqli, MYSQLI_OPT_LOCAL_INFILE, true);
    mysqli_options($mysqli, MYSQLI_OPT_CONNECT_TIMEOUT, 5);

    $ok = @mysqli_real_connect($mysqli, $host, $user, $pass, $name, (int) $port);
    if (!$ok) {
        $error = 'connect failed: ' . mysqli_connect_error();
        $log->write($error);
    } else {
        // Probe the server so the operator sees what they are talking to.
        $res = @mysqli_query($mysqli, 'SELECT VERSION() AS version');
        if ($res instanceof mysqli_result) {
            $row    = mysqli_fetch_assoc($res);
            $result = 'server reports version ' . ($row['version'] ?? '?');
        } elseif ($res === true) {
            $result = 'connected, but the server returned no result set';
        } else {
            $error = 'query failed: ' . mysqli_error($mysqli);
        }
        @mysqli_close($mysqli);
    }
}

if (($_POST['action'] ?? '') === 'avatar' && isset($_FILES['avatar'])) {
    $f = $_FILES['avatar'];
    if ($f['error'] !== UPLOAD_ERR_OK) {
        $error = 'upload failed (code ' . $f['error'] . ')';
    } elseif ($f['size'] > 256 * 1024) {
        $error = 'avatar too large';
    } else {
        // Whatever they send is stored with a .png name, so it can never be
        // executed by the web server.
        @mkdir(uploads_dir(), 0755, true);
        $dest = uploads_dir() . '/' . sha1_file($f['tmp_name']) . '.png';
        move_uploaded_file($f['tmp_name'], $dest);
        $notice = 'avatar stored as uploads/' . basename($dest);
        $log->write('avatar upload -> ' . $dest);
    }
}
?><!doctype html>
<meta charset="utf-8">
<title>Nimbus Panel</title>
<style>
 body{font:14px/1.6 ui-monospace,Menlo,Consolas,monospace;max-width:52rem;margin:2rem auto;padding:0 1rem;background:#0d1117;color:#c9d1d9}
 h1{font-size:1.25rem;color:#58a6ff} fieldset{border:1px solid #30363d;margin:1.2rem 0;padding:1rem}
 legend{color:#8b949e} label{display:inline-block;width:7rem} input{background:#010409;color:#c9d1d9;border:1px solid #30363d;padding:.25rem .4rem;width:16rem}
 button{padding:.35rem 1.1rem;margin-top:.6rem} .ok{color:#3fb950} .err{color:#f85149} small{color:#8b949e}
</style>
<h1>Nimbus Panel <small>&mdash; customer database health check</small></h1>

<?php if ($result): ?><p class="ok">[ok] <?= htmlspecialchars($result) ?></p><?php endif; ?>
<?php if ($error): ?><p class="err">[!!] <?= htmlspecialchars($error) ?></p><?php endif; ?>
<?php if ($notice): ?><p class="ok">[ok] <?= htmlspecialchars($notice) ?></p><?php endif; ?>

<form method="post">
  <fieldset>
    <legend>connect to a customer database</legend>
    <input type="hidden" name="action" value="dbtest">
    <p><label>host</label><input name="host" value="<?= htmlspecialchars($host) ?>"></p>
    <p><label>port</label><input name="port" value="<?= htmlspecialchars($port) ?>"></p>
    <p><label>user</label><input name="user" value="<?= htmlspecialchars($user) ?>"></p>
    <p><label>password</label><input name="pass" type="password" value=""></p>
    <p><label>database</label><input name="dbname" value="<?= htmlspecialchars($name) ?>"></p>
    <button type="submit">run health check</button>
  </fieldset>
</form>

<form method="post" enctype="multipart/form-data">
  <fieldset>
    <legend>operator avatar</legend>
    <input type="hidden" name="action" value="avatar">
    <p><input type="file" name="avatar"></p>
    <button type="submit">upload</button>
    <p><small>stored under <code>uploads/</code>, always renamed to
       <code>&lt;sha1&gt;.png</code> so it cannot be executed.</small></p>
  </fieldset>
</form>
