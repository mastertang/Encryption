<?php
namespace Encryption;

use Encryption\Exception\DesKeyCanNotNullException;
use Encryption\Exception\DesKeyLengthBiggerThanZeroException;
use Encryption\Exception\DesNotSupportThisAlgorithmException;
use Encryption\Exception\DesNotSupportThisIvSourceException;
use Encryption\Exception\DesNotSupportThisModeException;
use Encryption\Exception\McryptNotLoadException;

class Des
{

    /**
     * 加密
     * @param $source //要加密的字符串
     * @param $ivSource //创建向量需要的向量资源，值可查看php支持的向量资源的常量
     * @param $key //加密密钥
     * @param $algorithm //算法，具体可查看php支持的des方法常量
     * @param $algorithmDir //算法文件的文件夹地址
     * @param $mode //模式，可查看php支持的des模式
     * @param $modeDir //模式文件的文件夹地址
     * @param $iv //变量，引用保存当前加密生成的iv向量值，在解密时会使用到
     * @param $maxLength //key值得最大长度,引用保存当前加密计算的key值最大长度,在解密时会使用到
     * @return string
     * @throws DesNotSupportThisAlgorithmException
     * @throws DesNotSupportThisIvSourceException
     * @throws DesNotSupportThisModeException
     * @throws McryptNotLoadException
     * @throws DesKeyCanNotNullException
     */
    public static function encrypt(
        $source,
        $ivSource,
        $key,
        $algorithm,
        $algorithmDir,
        $mode,
        $modeDir,
        &$iv,
        &$maxLength
    )
    {
        if (empty($source)) {
            return "";
        }
        if (!extension_loaded('mcrypt')) {
            throw new McryptNotLoadException();
        }
        if (!self::supportMode($mode)) {
            throw new DesNotSupportThisModeException();
        }
        if (!self::supportIvSource($ivSource)) {
            throw new DesNotSupportThisIvSourceException();
        }
        if (!self::supportAlgorithm($algorithm)) {
            throw new DesNotSupportThisAlgorithmException();
        }
        if(empty($key)){
            throw new DesKeyCanNotNullException();
        }
        $encryptTd = mcrypt_module_open($algorithm, $algorithmDir, $mode, $modeDir);
        $ivSize = mcrypt_enc_get_iv_size($encryptTd);
        $encryptIv = mcrypt_create_iv($ivSize, $ivSource);
        $maxKeyLength = mcrypt_enc_get_key_size($encryptTd);
        $encryptKey = substr(md5($key), 0, $maxKeyLength);
        mcrypt_generic_init($encryptTd, $encryptKey, $encryptIv);
        $encryptedData = mcrypt_generic($encryptTd, $source);
        mcrypt_generic_deinit($encryptTd);
        mcrypt_module_close($encryptTd);
        $iv = $encryptIv;
        $maxLength = $maxKeyLength;
        return trim(chop($encryptedData));
    }

    /**
     * 解密
     * @param $encrypted //加密后的字符串
     * @param $ivSource //加密时获取到的iv向量
     * @param $key //解密key字符串
     * @param $maxKeyLength //加密时获取到的key的最大长度
     * @param $algorithm //算法，具体可查看php支持的des方法常量
     * @param $algorithmDir //算法文件的文件夹地址
     * @param $mode //模式，可查看php支持的des模式
     * @param $modeDir //模式文件的文件夹地址
     * @return string
     * @throws DesKeyLengthBiggerThanZeroException
     * @throws DesNotSupportThisAlgorithmException
     * @throws DesNotSupportThisIvSourceException
     * @throws DesNotSupportThisModeException
     * @throws McryptNotLoadException
     * @throws DesKeyCanNotNullException
     */
    public static function decrypt(
        $encrypted,
        $ivSource,
        $key,
        $maxKeyLength,
        $algorithm,
        $algorithmDir,
        $mode,
        $modeDir
    )
    {
        if (!extension_loaded('mcrypt')) {
            throw new McryptNotLoadException();
        }
        if (!self::supportMode($mode)) {
            throw new DesNotSupportThisModeException();
        }
        if (!self::supportAlgorithm($algorithm)) {
            throw new DesNotSupportThisAlgorithmException();
        }
        if(empty($key)){
            throw new DesKeyCanNotNullException();
        }
        if ($maxKeyLength <= 0) {
            throw new DesKeyLengthBiggerThanZeroException();
        }
        $encrypted = trim(chop($encrypted));
        $encryptTd = mcrypt_module_open($algorithm, $algorithmDir, $mode, $modeDir);
        $encryptKey = substr(md5($key), 0, $maxKeyLength);
        mcrypt_generic_init($encryptTd, $encryptKey, $ivSource);
        $encryptedData = mdecrypt_generic($encryptTd, $encrypted);
        $encryptedData = trim($encryptedData);
        mcrypt_generic_deinit($encryptTd);
        mcrypt_module_close($encryptTd);
        return $encryptedData;
    }

    /**
     * 支持此向量资源
     */
    private static function supportIvSource($ivSource)
    {
        $result = false;
        if (!is_int($ivSource)) {
            return false;
        }
        switch ($ivSource) {
            case MCRYPT_DEV_RANDOM:
            case MCRYPT_DEV_URANDOM:
            case MCRYPT_RAND:
                $result = true;
                break;
            default:
                break;
        }
        return $result;
    }

    /**
     * 支持加解密模式
     */
    private static function supportMode($mode)
    {
        $result = false;
        if (!is_string($mode)) {
            return false;
        }
        switch ($mode) {
            case MCRYPT_MODE_CBC:
            case MCRYPT_MODE_ECB:
            case MCRYPT_MODE_CFB:
            case MCRYPT_MODE_OFB:
            case MCRYPT_MODE_NOFB:
            case MCRYPT_MODE_STREAM:
                $result = true;
                break;
            default:
                break;
        }
        return $result;
    }

    /**
     * 检查算法
     */
    private static function supportAlgorithm($algorithm)
    {
        $result = false;
        if (!is_string($algorithm)) {
            return false;
        }
        switch ($algorithm) {
            case MCRYPT_3DES:
            case MCRYPT_ARCFOUR_IV:
            case MCRYPT_ARCFOUR:
            case MCRYPT_BLOWFISH:
            case MCRYPT_BLOWFISH_COMPAT:
            case MCRYPT_CAST_128:
            case MCRYPT_CAST_256:
            case MCRYPT_CRYPT:
            case MCRYPT_DES:
            case MCRYPT_ENIGNA:
            case MCRYPT_GOST:
            case MCRYPT_LOKI97:
            case MCRYPT_PANAMA:
            case MCRYPT_RC2:
            case MCRYPT_RIJNDAEL_128:
            case MCRYPT_RIJNDAEL_256:
            case MCRYPT_SAFER64:
            case MCRYPT_SAFER128:
            case MCRYPT_SAFERPLUS:
            case MCRYPT_SERPENT:
            case MCRYPT_THREEWAY:
            case MCRYPT_TRIPLEDES:
            case MCRYPT_TWOFISH:
            case MCRYPT_WAKE:
            case MCRYPT_XTEA:
            case MCRYPT_IDEA:
            case MCRYPT_MARS:
            case MCRYPT_RC6:
            case MCRYPT_SKIPJACK:
                $result = true;
                break;
            default:
                break;
        }
        return $result;
    }
}