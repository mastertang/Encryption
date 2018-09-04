<?php
include "../Des.php";

$testString = "this is my test string";
$key = "abcdefghijklmn";
$iv = null;
$length = 0;
$encrypted = \Encryption\Des::create()->encrypt(
    $testString,
    MCRYPT_DEV_RANDOM,
    $key,
    MCRYPT_3DES,
    "",
    MCRYPT_MODE_CBC,
    "",
    $iv,
    $length
);
//var_dump($encrypted);
$decrypted = \Encryption\Des::create()->decrypt(
    $encrypted,
    $iv,
    $key,
    $length,
    MCRYPT_3DES,
    "",
    MCRYPT_MODE_CBC,
    ""
);
var_dump($decrypted);