<?php
include "../Des.php";
include "../Exception/DesKeyLengthBiggerThanZeroException.php";
include "../Exception/DesNotSupportThisAlgorithmException.php";
include "../Exception/DesNotSupportThisModeException.php";
include "../Exception/DesNotSupportThisIvSourceException.php";
include "../Exception/DesKeyCanNotNullException.php";

$testString = "this is my test string";
$key = "abcdefghijklmn";
$iv = null;
$length = 0;
$encrypted = \Encryption\Des::encrypt(
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
$decrypted = \Encryption\Des::decrypt(
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