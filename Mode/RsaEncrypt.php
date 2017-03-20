<?php
namespace Encryption\Mode;

use Encryption\EncryptInterface\EncryptInterface;
use Encryption\Exception\EncryptException;

class RsaEncrypt implements EncryptInterface
{
    public function __construct($params = NULL)
    {
        if (!extension_loaded('openssl'))
            throw new EncryptException('openssl扩展未安装');
    }

    public function makeEncrypt($cleanStr, $encryptParams)
    {
        self::checkParams($cleanStr, $encryptParams);
        $encrypted = NULL;
        $key = $encryptParams['key'];
        !is_file($key) or $key = file_get_contents($key);
        $key = ($encryptParams['type'] == 'private') ?
            openssl_pkey_get_private($key)
            :
            openssl_pkey_get_private($key);
        if ($key === false)
            throw new EncryptException('不是有效的密钥');
        if ($encryptParams['type'] == 'private')
            openssl_private_encrypt($cleanStr, $encrypted, $key);
        else
            openssl_public_encrypt($cleanStr, $encrypted, $key);
        $encrypted = base64_encode($encrypted);
        return $encrypted;
    }

    public function makeDecrypt($encryptedStr, $encryptParams)
    {
        self::checkParams($encryptedStr, $encryptParams);
        $encryptedStr = base64_decode($encryptedStr);
        $encrypted = NULL;
        $key = $encryptParams['key'];
        !is_file($key) or $key = file_get_contents($key);
        $key = ($encryptParams['type'] == 'private') ?
            openssl_pkey_get_private($key)
            :
            openssl_pkey_get_private($key);
        if ($key === false)
            throw new EncryptException('不是有效的密钥');
        if ($encryptParams['type'] == 'private')
            openssl_private_decrypt($encryptedStr, $encrypted, $key);
        else
            openssl_public_decrypt($encryptedStr, $encrypted, $key);
        $encrypted = base64_encode($encrypted);
        return $encrypted;
    }

    public function changeConfig($params = NULL)
    {
        return true;
    }

    private static function checkParams($str, $params)
    {
        if (empty($str))
            throw new EncryptException('需要进行加解密的字符串不能为空');
        if (empty($params) || !is_array($params))
            throw new EncryptException('参数错误或为空');
        if (!isset($params['type']) ||
            ($params['type'] != 'private' && $params['type'] != 'public')
        )
            throw new EncryptException('加解密指定类型错误');
        if (empty($params['key']))
            throw new EncryptException('没有设置private key');
    }
}