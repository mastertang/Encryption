<?php
namespace Encryption\Mode;

use Encryption\EncryptInterface\EncryptInterface;
use Encryption\Exception\EncryptException;

class Md5Encrypt implements EncryptInterface
{
    private $config = NULL;
    private static $defaultConfig = [
        'salt_position' => 'tail'
    ];

    public function __construct($params = NULL)
    {
        if (empty($params))
            $params = __DIR__ . '/Config/Md5Config.php';
        $configArray = [];
        if (is_string($params) && file_exists($params))
            $configArray = include $params;
        elseif (is_array($params))
            $configArray = array_merge(self::$defaultConfig, $params);
        else
            $configArray = self::$defaultConfig;
        self::checkConfig($configArray);
        $this->config = $configArray;
    }

    private static function checkConfig($config)
    {
        if (!isset($config['salt_position']))
            throw new EncryptException('盐值添加位置不为空');
        if ($config['salt_position'] != 'tail' &&
            $config['salt_position'] != 'head' &&
            !($config['salt_position'] instanceof \Closure)
        )
            throw new EncryptException('盐值添加位置错误');
    }

    private static function checkParams(&$params)
    {
        if (!isset($params['salt']))
            $params['salt'] = '';
        if (!isset($config['salt_position']))
            $params['salt_position'] = self::$defaultConfig['salt_position'];
        if ($params['salt_position'] != 'tail' &&
            $params['salt_position'] != 'head' &&
            (!$params['salt_position'] instanceof \Closure)
        )
            $params['salt_position'] = self::$defaultConfig['salt_position'];
    }

    public function makeEncrypt($cleanStr, $encryptParams)
    {
        if (is_array($encryptParams))
            $encryptParams = array_merge($this->config, $encryptParams);
        self::checkParams($encryptParams);
        $encodedString = NULL;
        if ($encryptParams['salt_position'] == 'tail')
            $encodedString = md5($cleanStr . $encryptParams['salt']);
        if ($encryptParams['salt_position'] == 'head')
            $encodedString = md5($encryptParams['salt'], $cleanStr);
        if ($encryptParams['salt_position'] instanceof \Closure)
            $encodedString = $encryptParams['salt_position']($encryptParams['salt'], $cleanStr);
        return $encodedString;
    }

    public function makeDecrypt($encryptedStr, $encryptParams)
    {
        return true;
    }

    public function changeConfig($params = NULL)
    {
        if (!empty($params)) {
            if (is_array($params))
                $this->config = array_merge($this->config, $params);
        }
        return true;
    }
}