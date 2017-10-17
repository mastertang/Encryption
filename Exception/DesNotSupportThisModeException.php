<?php
namespace Encryption\Exception;
class DesNotSupportThisModeException extends \Exception
{
    /**
     * OpensslNotLoadException constructor.
     */
    public function __construct($message = "", $code = 0)
    {
        $message = "Des加解密算法不支持当前mode";
        if (PHP_SAPI == "cli") {
            $message = iconv("utf-8", "gb2312//IGNORE", $message);
        }
        parent::__construct($message, $code);
    }
}