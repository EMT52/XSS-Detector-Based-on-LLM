<?php
include 'function_definition.php';

$fm_url=$root_url . $_SERVER["PHP_SELF"];
$fm_url=rtrim($fm_url,"/");
$msg=$msg . "<br>Try this link: <a href=\"" . $fm_url . "\">" . $fm_url . "</a>";
die($msg);
echo(die($msg));
?>
