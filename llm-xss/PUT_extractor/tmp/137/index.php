<?php
include 'function_definition.php';

$_POST["del_url_array"] = $_GET['input'];
$del_url_array=$_POST["del_url_array"];
echo(json_encode(array("code" => 200,"msg" => "删除成功","type" => "success","icon" => "ok-sign","mode" => "delete","url" => $del_url_array),JSON_UNESCAPED_UNICODE));
?>
