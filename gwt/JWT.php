<?php

$gwt->exceptor('Test JWT::issue() #1', function () {
    $jwt = new \DOF\OFB\Auth\JWT;
    $jwt->issue();
}, \DOF\OFB\Auth\Exceptor\JWTExceptor::class, 'BAD_TOKEN_TTL_SETTING');

$gwt->exceptor('Test JWT::issue() #2', function () {
    $jwt = new \DOF\OFB\Auth\JWT;
    $jwt->setTTL(60)->issue();
}, \DOF\OFB\Auth\Exceptor\JWTExceptor::class, 'MISSING_OR_INVALID_SECRET_ID');

$gwt->exceptor('Test JWT::issue() #3', function () {
    $jwt = new \DOF\OFB\Auth\JWT;
    $jwt->setTTL(60)->setSecretId(1)->issue();
}, \DOF\OFB\Auth\Exceptor\JWTExceptor::class, 'MISSING_OR_INVALID_SECRET_KEY');

$gwt->eq('Test JWT::issue() #4', function () {
    $jwt = new \DOF\OFB\Auth\JWT;
    return $jwt->setTTL(60)->setSecretId(1)->setTimestamp(1600000000)->setSecretKey('xxx')->issue();
}, 'eyJ0eXAiOiJKV1QiLCJhbGciOiJzaGEyNTYifQ.W3siaXNzIjoiZG9mIiwibmJmIjoxNjAwMDAwMDAwLCJpYXQiOjE2MDAwMDAwMDAsInNpZCI6MSwidHphIjoiQ1NUIiwiZXhwIjoxNjAwMDAwMDYwfSxudWxsXQ.MDI0ZjdjZmJkNDg2YjUxZDdmZjU0MmUxYzNiNTg2YjkyNmI2ZmRkYmJkNzU5MjAzZmZjYTk4ZDMxZmM1ZGYxMA');

$gwt->eq('Test JWT::issue() #5', function () {
    $jwt = new \DOF\OFB\Auth\JWT;
    return $jwt->setTTL(60)->setSecretId(1)->setTimestamp(1600000000)->setSecretKey('xxx')->issue(['uid' => 1]);
}, 'eyJ0eXAiOiJKV1QiLCJhbGciOiJzaGEyNTYifQ.W3siaXNzIjoiZG9mIiwibmJmIjoxNjAwMDAwMDAwLCJpYXQiOjE2MDAwMDAwMDAsInNpZCI6MSwidHphIjoiQ1NUIiwiZXhwIjoxNjAwMDAwMDYwfSx7InVpZCI6MX1d.ZjVmYzAwMTMwZmY5ZjE5YzU0YmYxZGJlZGExNzdkMjA2ZTk0NGMzN2VjMWZkMjhjMmQ5MzVhMTNiMWMyMWMwYw');

$gwt->eq('Test JWT::parse() #1', function () {
    return DOF\OFB\Auth\Surrogate\JWT::parse('eyJ0eXAiOiJKV1QiLCJhbGciOiJzaGEyNTYifQ.W3siaXNzIjoiZG9mIiwibmJmIjoxNjAwMDAwMDAwLCJpYXQiOjE2MDAwMDAwMDAsInNpZCI6MSwidHphIjoiQ1NUIiwiZXhwIjoxNjAwMDAwMDYwfSxudWxsXQ.MDI0ZjdjZmJkNDg2YjUxZDdmZjU0MmUxYzNiNTg2YjkyNmI2ZmRkYmJkNzU5MjAzZmZjYTk4ZDMxZmM1ZGYxMA');
}, [
    'header' => ['typ' => 'JWT', 'alg' => 'sha256'],
    'claims' => ['iss' => 'dof', 'nbf' => 1600000000, 'iat' => 1600000000, 'sid' => 1, 'tza' => 'CST', 'exp' => 1600000060],
    'payload' => null,
    'signature' => 'MDI0ZjdjZmJkNDg2YjUxZDdmZjU0MmUxYzNiNTg2YjkyNmI2ZmRkYmJkNzU5MjAzZmZjYTk4ZDMxZmM1ZGYxMA',
]);

$gwt->eq('Test JWT::parse() #2', function () {
    return DOF\OFB\Auth\Surrogate\JWT::parse('eyJ0eXAiOiJKV1QiLCJhbGciOiJzaGEyNTYifQ.W3siaXNzIjoiZG9mIiwibmJmIjoxNjAwMDAwMDAwLCJpYXQiOjE2MDAwMDAwMDAsInNpZCI6MSwidHphIjoiQ1NUIiwiZXhwIjoxNjAwMDAwMDYwfSx7InVpZCI6MX1d.ZjVmYzAwMTMwZmY5ZjE5YzU0YmYxZGJlZGExNzdkMjA2ZTk0NGMzN2VjMWZkMjhjMmQ5MzVhMTNiMWMyMWMwYw');
}, [
    'header' => ['typ' => 'JWT', 'alg' => 'sha256'],
    'claims' => ['iss' => 'dof', 'nbf' => 1600000000, 'iat' => 1600000000, 'sid' => 1, 'tza' => 'CST', 'exp' => 1600000060],
    'payload' => ['uid' => 1],
    'signature' => 'ZjVmYzAwMTMwZmY5ZjE5YzU0YmYxZGJlZGExNzdkMjA2ZTk0NGMzN2VjMWZkMjhjMmQ5MzVhMTNiMWMyMWMwYw',
]);

$gwt->exceptor('Test JWT::verify() #1', function () {
    $jwt = new \DOF\OFB\Auth\JWT;
    $jwt->setSecretId(1)->setSecretKey('xxx');
    $jwt->verify('eyJ0eXAiOiJKV1QiLCJhbGciOiJzaGEyNTYifQ.W3siaXNzIjoiZG9mIiwibmJmIjoxNjAwMDAwMDAwLCJpYXQiOjE2MDAwMDAwMDAsInNpZCI6MSwidHphIjoiQ1NUIiwiZXhwIjoxNjAwMDA2MDAwfSx7InVpZCI6MX1d.ZmU1NWM5OTM2NGViNGQ1MDI5OTAwYmJhYzhmNDhiMTExOTJkZWIyNjk4ZTRkYzYxNThiYzU1MGE2MzdjM2FiOQ');
}, \DOF\OFB\Auth\Exceptor\ExpiredJWT::class);

$gwt->eq('Test JWT::verify() #2', function () {
    $jwt = new \DOF\OFB\Auth\JWT;
    $jwt->setSecretId(1)->setTimestamp(1)->setSecretKey('xxx');
    return $jwt->verify('eyJ0eXAiOiJKV1QiLCJhbGciOiJzaGEyNTYifQ.W3siaXNzIjoiZG9mIiwibmJmIjoxNjAxOTA2OTc4LCJpYXQiOjE2MDE5MDY5NzgsInNpZCI6MSwidHphIjoiQ1NUIiwiZXhwIjoxNjAxOTkzMzc4fSx7InVpZCI6MX1d.Y2ZiZmRhZWZlZmVjNmU3OGMxNDcwMDM4Mzc1YmI5NmUxYWY0N2FjMjMwOGRlYzFlOGMwNzFhMmZiNDgyOTg0Zg');
}, ['uid' => 1]);
