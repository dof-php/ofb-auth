<?php

$gwt->exceptor('Test HMAC::sign() #1', function () {
	$hmac = new \DOF\OFB\Auth\HMAC;
	$hmac->sign();
}, \DOF\OFB\Auth\Exceptor\HMACExceptor::class, 'MISSING_HMAC_MESSAGE_REALM');

$gwt->exceptor('Test HMAC::sign() #2', function () {
	$hmac = new \DOF\OFB\Auth\HMAC;
    $hmac->setRealm('test');
	$hmac->sign();
}, \DOF\OFB\Auth\Exceptor\HMACExceptor::class, 'MISSING_HMAC_MESSAGE_CLIENT');

$gwt->exceptor('Test HMAC::sign() #3', function () {
	$hmac = new \DOF\OFB\Auth\HMAC;
    $hmac->setRealm('test-realm');
    $hmac->setClient('test-client');
	$hmac->sign();
}, \DOF\OFB\Auth\Exceptor\HMACExceptor::class, 'MISSING_HMAC_MESSAGE_NONCE');

$gwt->exceptor('Test HMAC::sign() #4', function () {
	$hmac = new \DOF\OFB\Auth\HMAC;
    $hmac->setRealm('test-realm');
    $hmac->setClient('test-client');
    $hmac->setNonce('test-nonce');
	$hmac->sign();
}, \DOF\OFB\Auth\Exceptor\HMACExceptor::class, 'MISSING_HMAC_MESSAGE_TIMESTAMP');

$gwt->exceptor('Test HMAC::sign() #5', function () {
	$hmac = new \DOF\OFB\Auth\HMAC;
    $hmac->setRealm('test-realm');
    $hmac->setClient('test-client');
    $hmac->setNonce('test-nonce');
    $hmac->setTimestamp(\time());
	$hmac->sign();
}, \DOF\OFB\Auth\Exceptor\HMACExceptor::class, 'MISSING_SECRET_FOR_SIGNATURE');

$gwt->eq('Test HMAC::sign() #6', function () {
	$hmac = new \DOF\OFB\Auth\HMAC;
    $hmac->setRealm('test-realm');
    $hmac->setClient('test-client');
    $hmac->setNonce('test-nonce');
    $hmac->setTimestamp(1600000000);
    $hmac->setSecret('test-secret');
	return $hmac->sign();
}, '2957b42accf574289c98afef49c8480febb7e74f27afc1076a0124c3d9c1604d');
