<?php
namespace Encryption\Mode;

use Encryption\EncryptInterface\EncryptInterface;
use Encryption\Exception\EncryptException;

class DesEncrypt implements EncryptInterface
{
    private $config = [];
    private $defaultConfig = [
        'algorithm' => MCRYPT_TRIPLEDES,
        'algorithm_dir' => '',
        'mode' => MCRYPT_MODE_CBC,
        'mode_dir' => '',
        'iv_source' => MCRYPT_RAND
    ];

    public function __construct($config = NULL)
    {
        if (!extension_loaded('mcrypt'))
            throw new EncryptException('mcrypt 扩展未安装');
        $configArray = [];
        if (empty($config))
            $config = __DIR__ . '/Config/DesConfig.php';
        if (is_string($config) && file_exists($config))
            $configArray = include $config;
        elseif (is_array($config))
            $configArray = $config;
        $configArray = array_merge($this->defaultConfig, $configArray);
        self::checkParams('test', $configArray);
        $this->config = $configArray;
    }

    public function makeDecrypt($encryptedStr, $encryptParams)
    {
        if (is_array($encryptParams))
            $encryptParams = array_merge($this->config, $encryptParams);
        self::checkParams($encryptedStr, $encryptParams);
        $encryptedStr = trim(chop(base64_decode($encryptedStr)));
        $encryptKey = substr(md5($encryptParams['encryptKey']), 0, 24);
        $encryptTd = mcrypt_module_open(
            $encryptParams['algorithm'],
            $encryptParams['algorithm_dir'],
            $encryptParams['mode'],
            $encryptParams['mode_dir']
        );
        $encryptIv = mcrypt_create_iv(mcrypt_enc_get_iv_size($encryptTd), $encryptParams['iv_source']);
        mcrypt_generic_init($encryptTd, $encryptKey, $encryptIv);
        $encryptedData = mcrypt_generic($encryptTd, $encryptedStr);
        mcrypt_generic_deinit($encryptTd);
        mcrypt_module_close($encryptTd);
        return trim(chop($encryptedData));
    }

    public function makeEncrypt($cleanStr, $encryptParams)
    {
        if (is_array($encryptParams))
            $encryptParams = array_merge($this->config, $encryptParams);
        self::checkParams($cleanStr, $encryptParams);
        $encryptKey = substr(md5($encryptParams['encryptKey']), 0, 24);
        $encryptTd = mcrypt_module_open(
            $encryptParams['algorithm'],
            $encryptParams['algorithm_dir'],
            $encryptParams['mode'],
            $encryptParams['mode_dir']
        );
        $encryptIv = mcrypt_create_iv(mcrypt_enc_get_iv_size($encryptTd), $encryptParams['iv_source']);
        mcrypt_generic_init($encryptTd, $encryptKey, $encryptIv);
        $encryptedData = mcrypt_generic($encryptTd, $cleanStr);
        mcrypt_generic_deinit($encryptTd);
        mcrypt_module_close($encryptTd);
        return trim(chop(base64_encode($encryptedData)));
    }

    public function changeConfig($params = NULL)
    {
        if (!empty($params)) {
            if (is_array($params))
                $this->config = array_merge($this->config, $params);
        }
        return true;
    }

    private static function checkParams($cleanStr, &$encryptParams)
    {
        if (!is_string($cleanStr) || empty($cleanStr))
            throw new EncryptException('待处理字符串不能为空和必须为字符串');
        if (empty($encryptParams) || !is_array($encryptParams))
            throw new EncryptException('参数必须是数组');
        if (!isset($encryptParams['encryptKey']))
            throw new EncryptException('key不能为空');

        if (isset($encryptParams['algorithm'])) {
            if (!self::checkSupportAlgorithm($encryptParams['algorithm']))
                $encryptParams['algorithm'] = MCRYPT_TRIPLEDES;
        } else
            $encryptParams['algorithm'] = MCRYPT_TRIPLEDES;

        if (isset($encryptParams['algorithm_dir'])) {
            if (!self::checkPath($encryptParams['algorithm_dir']))
                $encryptParams['algorithm_dir'] = "";
        } else
            $encryptParams['algorithm_dir'] = "";

        if (isset($encryptParams['mode'])) {
            if (!self::checkMode($encryptParams['mode']))
                $encryptParams['mode'] = 'cbc';
        } else
            $encryptParams['mode'] = 'cbc';

        if (isset($encryptParams['mode_dir'])) {
            if (!self::checkPath($encryptParams['mode_dir']))
                $encryptParams['mode_dir'] = "";
        } else
            $encryptParams['mode_dir'] = "";

        if (isset($encryptParams['iv_source'])) {
            if (!self::checkIvSource($encryptParams['iv_source']))
                $encryptParams['iv_source'] = MCRYPT_RAND;
        } else
            $encryptParams['iv_source'] = MCRYPT_RAND;
    }

    private static function checkIvSource($ivSource)
    {
        $result = false;
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

    private static function checkPath($path)
    {
        return is_dir($path) ? true : false;
    }

    private static function checkMode($mode)
    {
        $result = false;
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

    private static function checkSupportAlgorithm($algorithm)
    {
        $result = false;
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