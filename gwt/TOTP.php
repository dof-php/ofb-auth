<?php

$gwt->unit('Test \DOF\OFB\Auth\TOTP::getSecret()', function ($t) {
	$t->true(function () {
		$secret = \DOF\OFB\Auth\TOTP::getSecret();
		return \is_string($secret) && (\strlen($secret) === 40);
	});
	$t->true(function () {
		$secret = \DOF\OFB\Auth\TOTP::getSecret(32);
		return \is_string($secret) && (\strlen($secret) === 32);
	});
	$t->true(function () {
		$secret = \DOF\OFB\Auth\TOTP::getSecret(0);
		return \is_string($secret) && (\strlen($secret) === 32);
	});
	$t->true(function () {
		$secret = \DOF\OFB\Auth\TOTP::getSecret(-1);
		return \is_string($secret) && (\strlen($secret) === 32);
	});
});

$gwt->unit('Test \DOF\OFB\Auth\TOTP::getSecretByID()', function ($t) {
	$t->true(function () {
		$secret = \DOF\OFB\Auth\TOTP::getSecretByID(1);
		return \is_string($secret) && (\strlen($secret) === 40);
	});
	$t->true(function () {
		$secret = \DOF\OFB\Auth\TOTP::getSecretByID(2, 32);
		return \is_string($secret) && (\strlen($secret) === 32);
	});
	$t->true(function () {
		$secret = \DOF\OFB\Auth\TOTP::getSecretByID(2, 0);
		return \is_string($secret) && (\strlen($secret) === 32);
	});
	$t->true(function () {
		$secret = \DOF\OFB\Auth\TOTP::getSecretByID(2, -1);
		return \is_string($secret) && (\strlen($secret) === 32);
	});
});

$gwt->unit('Test \DOF\OFB\Auth\TOTP::getSecretByKey()', function ($t) {
	$t->true(function () {
		$secret = \DOF\OFB\Auth\TOTP::getSecretByKey('13344445555');
		return \is_string($secret) && (\strlen($secret) === 40);
	});
	$t->true(function () {
		$secret = \DOF\OFB\Auth\TOTP::getSecretByKey('13344445555', 32);
		return \is_string($secret) && (\strlen($secret) === 32);
	});
	$t->true(function () {
		$secret = \DOF\OFB\Auth\TOTP::getSecretByKey('13344445555', 0);
		return \is_string($secret) && (\strlen($secret) === 32);
	});
	$t->true(function () {
		$secret = \DOF\OFB\Auth\TOTP::getSecretByKey('13344445555', -1);
		return \is_string($secret) && (\strlen($secret) === 32);
	});
});
