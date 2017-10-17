<?php
include "../JWT.php";
include "../Des.php";
include "../Md5.php";
include "../Rsa.php";
include "../Exception/DesKeyLengthBiggerThanZeroException.php";
include "../Exception/DesNotSupportThisAlgorithmException.php";
include "../Exception/DesNotSupportThisModeException.php";
include "../Exception/DesNotSupportThisIvSourceException.php";
include "../Exception/DesKeyCanNotNullException.php";
include "../Exception/JWTDecryptErrorException.php";
include "../Exception/JWTFailedException.php";
include "../Exception/JWTParamsErrorException.php";
include "../Exception/JWTSignatureErrorException.php";
include "../Exception/JWTStringErrorException.php";

$testString = "this is my test string";
$key = "abcdefghijklmn";
$iv = null;
$length = 0;
$jwt = new \Encryption\JWT();
$encrypted = $jwt->encrypt(//加密
    ["alg" => "des"],
    ['a' => "test", 't' => 'test'],
    "hahaha",
    function ($playload) use ($key, &$iv, &$length) {
        $string = json_encode($playload);
        $encoded = \Encryption\Des::encrypt(
            $string,
            MCRYPT_DEV_RANDOM,
            $key,
            MCRYPT_3DES,
            "",
            MCRYPT_MODE_CBC,
            "",
            $iv,
            $length
        );
        return $encoded;
    }
);
//var_dump($decrypted);
$decrypted = $jwt->decrypt(//解码
    $encrypted,
    "hahaha",
    function ($header, $payLoad, $signature) use ($key, $iv, $length) {
        var_dump($key);
        $decoded = \Encryption\Des::decrypt(
            $payLoad,
            $iv,
            $key,
            $length,
            MCRYPT_3DES,
            "",
            MCRYPT_MODE_CBC,
            ""
        );
        var_dump($decoded);
        return $decoded;
    });
var_dump($jwt->integrityBreak());     //根据签名判断是否数据完整
var_dump($jwt->getDecodedHeader());   //获取解码后的头部信息
var_dump($jwt->getDecodedPlayLoad()); //获取解码后的数据信息
var_dump($jwt->getDecodedSignature());//获取解码后的签名信息
var_dump($jwt->getOriginSignature()); //获取正确的签名信息
