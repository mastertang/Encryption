<?php
return [
    'salt_position' => 'tail',//加盐位置，默认在tail尾部，值可为head(头部)、tail(尾部)、function($salt,$string){**** return $encrypted_str}(匿名函数)
];