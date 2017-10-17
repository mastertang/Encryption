<?php
namespace Encryption\Exception;
class DesKeyCanNotNullException extends \Exception
{
    /**
     * OpensslNotLoadException constructor.
     */
    public function __construct($message = "", $code = 0)
    {
        $message = "Des的密钥不能为空";
        if (PHP_SAPI == "cli") {
            $message = iconv("utf-8", "gb2312//IGNORE", $message);
        }
        parent::__construct($message, $code);
    }
}