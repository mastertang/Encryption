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
            openssl_pkey_get_public($key);
        $keyDetails = openssl_pkey_get_details($key);
        if ($key === false)
            throw new EncryptException('不是有效的密钥');
        $cleanStr = self::stringSplits($cleanStr, ($keyDetails['bits'] / 8 - 11));
        $encrypted = [];
        $sizeString = sizeof($cleanStr);
        for ($i = 0; $i < $sizeString; $i++) {
            if ($encryptParams['type'] == 'private')
                openssl_private_encrypt($cleanStr[$i], $encrypted[$i], $key);
            else
                openssl_public_encrypt($cleanStr[$i], $encrypted[$i], $key);
        }
        return base64_encode(implode('', $encrypted));
    }

    public function makeDecrypt($encryptedStr, $encryptParams = [])
    {
        self::checkParams($encryptedStr, $encryptParams);
        $encryptedStr = base64_decode($encryptedStr);
        $encrypted = NULL;
        $key = $encryptParams['key'];
        !is_file($key) or $key = file_get_contents($key);
        $key = ($encryptParams['type'] == 'private') ?
            openssl_pkey_get_private($key)
            :
            openssl_pkey_get_public($key);
        if ($key === false)
            throw new EncryptException('不是有效的密钥');
        $keyDetails = openssl_pkey_get_details($key);
        $encryptedStr = self::stringSplits($encryptedStr, ($keyDetails['bits']/8));
        $sizeStirng = sizeof($encryptedStr);
        $encrypted = [];
        for ($i = 0; $i < $sizeStirng; $i++) {
            if ($encryptParams['type'] == 'private') {
                openssl_private_decrypt($encryptedStr[$i], $encrypted[$i], $key);
            }else
                openssl_public_decrypt($encryptedStr[$i], $encrypted[$i], $key);
        }
        if ($sizeStirng == 1) $encrypted = $encrypted[0];
        return implode('',$encrypted);
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

    private static function stringSplits($string, $len)
    {
        return str_split($string, $len);
    }
}