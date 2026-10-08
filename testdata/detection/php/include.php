<?php
include($_GET['page'] . ".php");
$data = unserialize($_POST['data']);
echo file_get_contents("/data/reports/" . $_GET['file']);
