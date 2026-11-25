<?php
include 'function_definition.php';

$_GET["img"] = $_GET['input'];
$src=$_GET["img"];
$src=$config["path"] . $src;
header("Location:thumb.php?img=" . $src);
?>
