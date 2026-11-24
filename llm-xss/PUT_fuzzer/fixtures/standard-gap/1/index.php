<?php
// Local XSS test fixture: a preview endpoint accepts a JSON object in input.
// The html field is deliberately rendered without output encoding.
require_once __DIR__ . '/function_definition.php';

$input = isset($_GET['input']) ? $_GET['input'] : '';
$card = json_decode($input, true);
$html = '';
if (is_array($card) && isset($card['html']) && is_string($card['html'])) {
    $html = $card['html'];
}
header('Content-Type: text/html; charset=UTF-8');
echo '<div class="preview">' . $html . '</div>';
