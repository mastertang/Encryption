<?php

namespace EncryptionSDK;

/**
 * Class Des
 * @package Encryption
 */
class Des
{

    /**
     * 加密
     *
     * @param $string
     * @param $desKey
     * @return string
     */
    public function encrypt(
        $string,
        $desKey
    )
    {
        $data = openssl_encrypt(
            $string,
            'DES-ECB',
            $desKey,
            OPENSSL_RAW_DATA
        );
        $data = base64_encode($data);
        return $data;
    }

    /**
     * 解密
     *
     * @param $encodeString
     * @param $desKey
     * @return string
     */
    public function decrypt(
        $encodeString,
        $desKey
    )
    {
        $data = openssl_decrypt(
            base64_decode($encodeString),
            'DES-ECB',
            $desKey,
            OPENSSL_RAW_DATA
        );
        return $data;
    }

}