# 加密

#### 异常：
* 异常文件 : EncryptException.php 类 : EncryptException

* 支持的解压缩类型
```
1.Zip
```

* 配置文件
```
1.Des配置文件 DesConfig.php 内容为:
    [
        'algorithm' => MCRYPT_TRIPLEDES,//算法
        'algorithm_dir' => '',          //算法文件夹路径
        'mode' => MCRYPT_MODE_CBC,      //模式
        'mode_dir' => '',               //mode文件夹路径
        'iv_source' => MCRYPT_RAND      //iv向量参数
    ]
2.Md5配置文件 Md5Config.php 内容为:
    [
        'salt_position' => 'tail',//加盐位置，默认在tail尾部，
                值可为head(头部)、tail(尾部)、function($salt,$string){**** return $encrypted_str}(匿名函数)
    ]
```
###### 接口
####### 主接口
* 1 . encryptStart($encryptName = NULL, $encryptParams = NULL) //初始化，并选择加密类型
```
    $encryptName = 可选,加解密算法有Md5,Des,Rsa,默认使用Md5
    $encryptParams = 可选，每个算法的配置不同,默认使用默认配置
    例子: Encryption::encryptStart('Des',[......]);
```
* 2 . encrypt($cleanStr, $encryptParams = []) //加密
```
    $cleanStr = 需要加密的明文
    $encryptParams = 可选，加密时的配置，每个算法都不同,默认使用默认配置
    例子: $Encryption->encrypt('hello',[......]);
```
* 3 . decrypt($encryptedStr, $encryptParams = []) //解密
```
    $encryptedStr = 需要解密的明文
    $encryptParams = 可选,解密时的配置，每个算法都不同,默认使用默认配置
    例子: $Encryption->decrypt('U9oYnm3et',[......]);
```
* 4 .  changeConfig($params = NULL) //修改配置信息
``` 
    $params = 可选,对应算法的配置信息
```
* 5 . encryptionSwift($encryptName) //更改当前算法
```
    $encryptName = 算法名,Md5、Des、Rsa
```
####### Md5
* 1 . makeEncrypt($cleanStr, $encryptParams = []) //加密
```
    $cleanStr = 需要加密的明文
    $encryptParams = 可选，加密时的配置，每个算法都不同,默认使用默认配置,
    例子 : [
            'salt_position',盐的位置，head表示在前面加盐，tail表示尾部加盐；也可以是匿名函数,用户自定义加密方法和操作，第一个参数为盐值
            'salt' => 盐,如果不加盐可以为空
            ]
    例子: $Encryption->decrypt('hello',[......]);
```
* 3 . makeDecrypt($encryptedStr, $encryptParams = []) //解密
```
    返回:true
```
####### Des
* 1 . makeEncrypt($cleanStr, $encryptParams) //加密
```
    $cleanStr = 需要加密的明文
    $encryptParams = 加密时的配置，每个算法都不同,默认使用默认配置,
    例子 : [
               'algorithm'=>算法              可选
               'algorithm_dir=>算法文件的文件夹 可选
               'mode'=>模式类型                可选
               'mode_dir'=>mode文件的文件夹     可选
               'iv_source'=>iv向量参数         可选
               'encryptKey'=>加密的密钥        必填
            ]
    例子: $Encryption->encrypt('hello',[......]);
    返回 : [
              'code' => base64_encode(加密后的字符串),
              'iv' => 加密时的iv向量,
              'keySize' => 密码可用最大长度
           ];
```
* 3 . makeDecrypt($encryptedStr, $encryptParams) //解密
```
    $encryptedStr = 被加密后的字符串
    $encryptParams = 解密时的配置，每个算法都不同,默认使用默认配置,
        例子 : [
                   'algorithm'=>算法                    可选
                   'algorithm_dir=>算法文件的文件夹       可选
                   'mode'=>模式类型                      可选
                   'mode_dir'=>mode文件的文件夹           可选
                   'encryptKey'=>加密的密钥               必填
                   'iv' =>加密时的向量,                   必填     
                   'keySize'=>加密时获得的密码可用最大长度   必填
                ]
        例子: $Encryption->decrypt('hello',[......]);
    返回:解密后明文
```
####### Rsa
* 1 . makeEncrypt($cleanStr, $encryptParams) //加密
```
    $cleanStr = 需要加密的明文
    $encryptParams = 加密时的配置，每个算法都不同,默认使用默认配置,
    例子 : [
             'key'=>加密key文件的路径或者直接是加密字符串                  必填
             'type=>'private'表示加密用的私钥,'public'表示加密用的是公钥   必填
           ]
    例子: $Encryption->encrypt('hello',[......]);
    返回 : base64_encode(加密后的字符串)
```
* 3 . makeDecrypt($encryptedStr, $encryptParams) //解密
```
    $encryptedStr = 被加密后的字符串
    $encryptParams = 解密时的配置，每个算法都不同,默认使用默认配置,
    例子 : [
             'key'=>解密key文件的路径或者直接是解密字符串                  必填
             'type=>'private'表示解密用的私钥,'public'表示解密用的是公钥   必填
           ]
        例子: $Encryption->decrypt('hello',[......]);
    返回:解密后明文
```

    