<?php
include 'function_definition.php';

$_GET["img"] = $_GET['input'];
$src=APP_ROOT . $_GET["img"];
die(file_get_contents($src,True));
echo(die(file_get_contents($src,True)));
?>
