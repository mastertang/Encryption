<?php
include "../Md5.php";
$testString = "this is my test string";
var_dump(\Encryption\Md5::encrypt(
    1,
    "",
    "ad",
    false
));