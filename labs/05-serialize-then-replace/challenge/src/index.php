<?php
require __DIR__ . '/lib.php';

$user = current_user();
if ($user !== null) {
    header('Location: profile.php');
    exit;
}

page('sign up', <<<HTML
<p>Store your pictures. Tell the world who you are.</p>
<form method="post" action="register.php">
  <fieldset><legend>create an account</legend>
    <label>username <input name="username" value="" autocomplete="off"></label>
    <label>password <input name="password" type="password" autocomplete="off"></label>
    <p><button>sign up</button></p>
  </fieldset>
</form>
HTML);
