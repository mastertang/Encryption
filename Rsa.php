<?php

namespace EncryptionSDK;

/**
 * Class Rsa
 * @package Encryption
 */
class Rsa
{
    /**
     * @var string 错误信息
     */
    public $errMessage = '';

    /**
     * 私钥类型
     */
    const KEY_PRIVATE = 0x01;

    /**
     * 公钥类型
     */
    const KEY_PUBLIC = 0x02;

    /**
     * Rsa加密
     * @param $source
     * @param $key
     * @param int $type
     * @return bool|string
     */
    public function encrypt($source, $key, $type = self::KEY_PRIVATE)
    {
        if (!extension_loaded('openssl')) {
            $this->errMessage = 'openssl模块未加载';
            return false;
        }
        $encrypted = NULL;
        !is_file($key) or $key = file_get_contents($key);
        if (empty($key)) {
            $this->errMessage = 'rsa key为空';
            return false;
        }
        $key = ($type == self::KEY_PRIVATE) ?
            openssl_pkey_get_private($key)
            :
            openssl_pkey_get_public($key);
        if ($key === false) {
            $this->errMessage = 'rsa key错误';
            return false;
        }
        $keyDetails = openssl_pkey_get_details($key);
        $splits     = str_split($source, ($keyDetails['bits'] / 8 - 11));
        $encrypted  = [];
        $size       = sizeof($splits);
        if ($type == self::KEY_PRIVATE) {
            for ($i = 0; $i < $size; $i++) {
                openssl_private_encrypt($splits[$i], $encrypted[$i], $key);
            }
        } else {
            for ($i = 0; $i < $size; $i++) {
                openssl_public_encrypt($splits[$i], $encrypted[$i], $key);
            }
        }
        return implode("", $encrypted);
    }

    /**
     * Rsa解密
     *
     * @param $encrypted
     * @param $key
     * @param int $type
     * @return bool|string
     */
    public function decrypt($encrypted, $key, $type = self::KEY_PRIVATE)
    {
        if (!extension_loaded('openssl')) {
            $this->errMessage = 'openssl模块未加载';
            return false;
        }
        !is_file($key) or $key = file_get_contents($key);
        if (empty($key)) {
            $this->errMessage = 'rsa key为空';
            return false;
        }
        $key = ($type == self::KEY_PRIVATE) ?
            openssl_pkey_get_private($key)
            :
            openssl_pkey_get_public($key);
        if ($key === false) {
            $this->errMessage = 'rsa key错误';
            return false;
        }
        $keyDetails = openssl_pkey_get_details($key);
        $spilt      = str_split($encrypted, ($keyDetails['bits'] / 8));
        $size       = sizeof($spilt);
        $decrypted  = [];
        if ($type == self::KEY_PRIVATE) {
            for ($i = 0; $i < $size; $i++) {
                openssl_private_decrypt($spilt[$i], $decrypted[$i], $key);
            }
        } else {
            for ($i = 0; $i < $size; $i++) {
                openssl_public_decrypt($spilt[$i], $decrypted[$i], $key);
            }
        }
        if ($size == 1) {
            return $decrypted[0];
        }
        return implode('', $decrypted);
    }

    /**
     * 创建rsa钥匙
     *
     * @param string $disgestAlg
     * @param int $keyBits
     * @param int $keyType
     * @return array
     */
    public function createRsaKey($disgestAlg = 'sha512', $keyBits = 4096, $keyType = OPENSSL_KEYTYPE_RSA)
    {
        $config = [
            'digest_alg'       => $disgestAlg,
            'private_key_bits' => $keyBits,
            'private_key_type' => $keyType
        ];

        $res = openssl_pkey_new($config);
        openssl_pkey_export($res, $privKey);
        $pubKey = openssl_pkey_get_details($res);
        $pubKey = $pubKey["key"];

        return [
            'private' => $privKey,
            'public'  => $pubKey
        ];
    }
}