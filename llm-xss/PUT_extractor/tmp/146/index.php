<?php
include 'function_definition.php';

$_GET["history"] = $_GET['input'];
$dw="../" . $_GET["history"];
header("Content-Length:" . filesize($dw));
?>
