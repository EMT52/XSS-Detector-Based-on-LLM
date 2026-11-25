<?php
include 'function_definition.php';

$_GET["hash"] = $_GET['input'];
$delHash=$_GET["hash"];
die(json_encode(array("code" => 404,"msg" => "删除失败","type" => "danger","icon" => "exclamation-sign","mode" => "delete","url" => $delHash),JSON_UNESCAPED_UNICODE));
echo(> 404,"msg" => "删除失败","type" => "danger","icon" => "exclamation-sign","mode" => "delete","url" => $delHash),JSON_UNESCAPED_UNICODE)));
?>
