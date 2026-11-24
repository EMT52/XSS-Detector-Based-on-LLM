<?php
// A small, deliberately vulnerable local fixture for pipeline verification.
$name = isset($_GET['name']) ? $_GET['name'] : '';
echo '<h1>' . $name . '</h1>';
