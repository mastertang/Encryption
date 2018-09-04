<?php

namespace Encryption;

class JWT
{
    public $errMessage = '';
    /**
     * 解密后的数据
     */
    protected $decodedData = null;

    /**
     * 完整性是否被破坏
     */
    protected $signatureError = false;

    /**
     * 解密后的JWT头部
     */
    protected $decodedHeader = null;

    /**
     * 解密后的JWT数据部分
     */
    protected $decodedPlayLoad = null;

    /**
     * 解密后的JWT签名部分
     */
    protected $decodedSignature = null;

    /**
     * 正确JWT签名
     */
    protected $originSignature = null;

    /**
     * 初始化
     */
    public function initial()
    {
        $this->signatureError   = false;
        $this->decodedHeader    = null;
        $this->decodedPlayLoad  = null;
        $this->decodedSignature = null;
        $this->originSignature  = null;
    }

    /**
     * 获取解密后的数据
     */
    public function getDecodedPlayLoad()
    {
        return $this->decodedPlayLoad;
    }

    /**
     * 获取解密后的头部
     */
    public function getDecodedHeader()
    {
        return $this->decodedHeader;
    }

    /**
     * 获取解密后的签名
     */
    public function getDecodedSignature()
    {
        return $this->decodedSignature;
    }

    /**
     * 获取解密后的签名
     */
    public function getOriginSignature()
    {
        return $this->originSignature;
    }

    /**
     * 检查数据完整性
     */
    public function integrityBreak()
    {
        return $this->signatureError;
    }

    /**
     * 加密
     */
    public function encrypt($header, $payload, $hashSecret, $handler = null)
    {
        if (is_null($payload) || empty($header) || !is_array($header)) {
            $this->errMessage = '信息不能为空';
            return false;
        }
        $header = base64_encode(json_encode($header));
        if (is_callable($handler)) {
            $payLoad = base64_encode(call_user_func_array($handler, [$payload]));
        } else {
            $payLoad = base64_encode(json_encode($payload));
        }
        $signature = hash('sha256', $header . "." . $payLoad . $hashSecret);
        if (!$signature || !$payLoad || !$header) {
            $this->errMessage = "加密失败";
            return false;
        }
        return "{$header}.{$payLoad}.{$signature}";
    }

    /**
     * 解密
     */
    public function decrypt($encrypted, $hashSecret, $handler = null)
    {
        $JWT = explode(".", $encrypted);
        if (empty($JWT) || sizeof($JWT) != 3) {
            $this->errMessage = "不是正确的JWT字符串";
            return false;
        }
        list($header, $payLoad, $signature) = $JWT;
        $header    = json_decode(base64_decode($header), true);
        if (!is_array($header) || empty($header)) {
            $this->errMessage = "JWT字符串格式错误";
            return false;
        }
        $nowSignature = hash('sha256', $JWT[0] . "." . $JWT[1] . $hashSecret);
        if ($nowSignature != $signature) {
            $this->signatureError = true;
        }
        $data = null;
        if (is_callable($handler)) {
            $data = json_decode(call_user_func_array($handler, [$header, base64_decode($payLoad), $signature]), true);
        } else {
            $data = json_decode(base64_decode($payLoad), true);
        }
        $this->decodedData      = $data;
        $this->decodedHeader    = $header;
        $this->decodedPlayLoad  = $data;
        $this->decodedSignature = $signature;
        $this->originSignature  = $nowSignature;
        return $data;
    }
}