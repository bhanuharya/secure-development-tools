<?php
system("ping -c 1 " . $_GET['host']);
$output = shell_exec("nslookup " . $_POST['name']);
echo $output;
