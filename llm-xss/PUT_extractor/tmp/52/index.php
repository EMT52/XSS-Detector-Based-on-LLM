<?php
include 'function_definition.php';

$_GET["key"] = $_GET['input'];
$hide_original=$_GET["key"];
$real_path=APP_ROOT . urlHash($hide_original,1,crc32($config["hide_key"]));
echo(file_get_contents($real_path));
?>
