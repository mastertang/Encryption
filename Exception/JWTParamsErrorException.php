<?php
namespace Encryption\Exception;
class JWTParamsErrorException extends \Exception
{
    /**
     * OpensslNotLoadException constructor.
     */
    public function __construct($message = "", $code = 0)
    {
        $message = "JWT加解密方法参数错误,不符合要求";
        if (PHP_SAPI == "cli") {
            $message = iconv("utf-8", "gb2312//IGNORE", $message);
        }
        parent::__construct($message, $code);
    }
}