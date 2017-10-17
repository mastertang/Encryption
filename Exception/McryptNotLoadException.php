<?php
namespace Encryption\Exception;
class McryptNotLoadException extends \Exception
{
    /**
     * OpensslNotLoadException constructor.
     */
    public function __construct($message = "", $code = 0)
    {
        $message = "mcrypt扩展并未安装";
        if (PHP_SAPI == "cli") {
            $message = iconv("utf-8", "gb2312//IGNORE", $message);
        }
        parent::__construct($message, $code);
    }

}