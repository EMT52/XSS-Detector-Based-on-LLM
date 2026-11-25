<?php
include 'function_definition.php';

$_GET["dw"] = $_GET['input'];
$dw="../" . $_GET["dw"];
header("Content-Length:" . filesize($dw));
?>
