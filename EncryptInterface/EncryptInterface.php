<?php
namespace Encryption\EncryptInterface;
interface EncryptInterface
{
    public function makeEncrypt($cleanStr, $encryptParams);

    public function makeDecrypt($encryptedStr, $encryptParams);

    public function changeConfig($params = NULL);
}