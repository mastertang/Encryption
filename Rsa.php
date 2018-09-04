<?php

namespace Encryption;

class Rsa
{
    public $errMessage = '';
    const KEY_PRIVATE = 0x01;
    const KEY_PUBLIC  = 0x02;

    /**
     * 加密
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
     * 解密
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
        if ($size == 1) $decrypted = $decrypted[0];
        return implode('', $decrypted);
    }
}