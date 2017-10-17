<?php
namespace Encryption;

class Md5
{
    /**
     * 盐值添加到头部
     */
    const SALT_HEAD = 0x01;
    /**
     * 盐值添加到尾部
     */
    const SALT_TAIL = 0x02;

    /**
     * 加密
     */
    public static function encrypt($source, $salt = "", $position = self::SALT_HEAD, $output = null)
    {
        if (!is_string($source) || strlen($source) <= 0) {
            return "";
        }
        if ($position != self::SALT_HEAD && $position != self::SALT_TAIL) {
            $position = self::SALT_HEAD;
        }
        if (!is_string($salt)) {
            $salt = "";
        }
        switch ($position) {
            case self::SALT_HEAD:
                return md5($salt . $source, $output);
                break;
            case self::SALT_TAIL:
                return md5($source . $salt, $output);
                break;
            default:
                return "";
                break;
        }
    }
}