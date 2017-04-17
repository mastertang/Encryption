<?php
namespace Encryption;

use Encryption\Exception\EncryptException;

class Encryption
{
    private static $encrypter = NULL;

    public static function encryptStart($encryptName = NULL, $encryptParams = NULL)
    {
        if (empty($encryptName))
            $encryptName = 'Md5';
        $encryptName = "{$encryptName}Encrypt";
        $nameSpace = "Encryption\\Mode\\" . $encryptName;
        $encryptPath = __DIR__ . '/Mode/' . "{$encryptName}.php";
        if (!file_exists($encryptPath))
            throw new EncryptException('加密方式文件不存在');
        require $encryptPath;
        if (!class_exists($nameSpace))
            throw new EncryptException('加密类不存在');
        $handler = new Encryption(new $nameSpace($encryptParams));
        return $handler;
    }

    public function __construct(&$encrypter)
    {
        self::$encrypter = $encrypter;
    }

    public function encrypt($cleanStr, $encryptParams = [])
    {
        return self::$encrypter->makeEncrypt($cleanStr, $encryptParams);
    }

    public function decrypt($encryptedStr, $encryptParams = [])
    {
        return self::$encrypter->makeDecrypt($encryptedStr, $encryptParams);
    }

    public function changeConfig($params = NULL)
    {
        return self::$encrypter->changeConfig($params);
    }

    public function encryptionSwift($encryptName)
    {
        if (!empty($encryptName) && is_string($encryptName)) {
            if (!empty(self::$encrypter))
                self::$encrypter = NULL;
            $encryptName = "{$encryptName}Encrypt";
            $encryptPath = __DIR__ . '/Mode/' . "{$encryptName}.php";
            if (!file_exists($encryptPath))
                throw new EncryptException('加密方式文件不存在');
            require $encryptPath;
            if (!class_exists($encryptName))
                throw new EncryptException('加密类不存在');
            self::$encrypter = new $encryptName();
            return true;
        } else
            return false;
    }
}