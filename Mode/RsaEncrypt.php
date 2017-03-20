<?php
namespace Encryption\Mode;

use Encryption\EncryptInterface\EncryptInterface;

class RsaEncrypt implements EncryptInterface
{
    public function makeDecrypt($encryptedStr, $encryptParams)
    {
    }

    public function makeEncrypt($cleanStr, $encryptParams)
    {
    }

    public function changeConfig($params = NULL)
    {
    }
}