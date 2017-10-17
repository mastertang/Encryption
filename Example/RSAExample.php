<?php
/**
 * openssl 生成密钥命令:
 * openssl genrsa -out rsa_private_key.pem(文件路径) 1024(密钥长度)
 *
 * openssl 生成公钥命令
 * openssl rsa -in rsa_private_key.pem(之前生成的密钥) -pubout -out rsa_public_key.pem(公钥文件路径)
 *
 * 这公钥和密钥是一对的，公钥只能从密钥中生成
 */

include "../Rsa.php";
include "../Exception/RsaKeyEmptyException.php";
include "../Exception/RsaKeyErrorException.php";
include "../Exception/OpensslNotLoadException.php";

$testString = "this is my test string";
$encrypted = null;
$encrypted = \Encryption\Rsa::encrypt($testString, __DIR__ . "/rsa_private_key_256.pem");
var_dump($encrypted);
$decrypted = \Encryption\Rsa::decrypt($encrypted,__DIR__."/rsa_public_key_256.pem",\Encryption\Rsa::KEY_PUBLIC);
var_dump($decrypted);