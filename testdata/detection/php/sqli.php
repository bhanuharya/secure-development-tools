<?php
$conn = mysqli_connect("db", "app", "S3cret!Passw0rd", "app");
$result = mysqli_query($conn, "SELECT * FROM users WHERE id = " . $_GET['id']);
echo json_encode(mysqli_fetch_all($result));
