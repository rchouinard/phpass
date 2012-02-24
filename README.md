PHPass: PHP Password Library
============================

What is PHPass?
---------------

PHPass is a PHP library designed to ease the tasks associated with working with passwords. It is capable of generating strong cryptographic hashes, verifying supplied passwords against those hashes, and calculating the relative strength of a given password.

Installation
------------

Either download a tarball or clone the project from GitHub and add the library folder to you include path, or use [the PEAR channel](http://rchouinard.github.com/pear/):

```bash
pear channel-discover rchouinard.github.com/pear
pear install rych/PHPass-2.0.0
```

Alternatively, you may use the [Composer](http://getcomposer.org) package manager to install the [rych/phpass](http://packagist.org/packages/rych/phpass) package.

Hashing passwords
-----------------

The library provides the ability to generate strong cryptographic hashes of user passwords using a variety of methods. Each method may be customized as needed, and may also be combined with HMAC hashing when using the base class.

### Examples

```php
<?php
// Default configuration - bcrypt adapter, 2^12 (4,096) iterations
$phpassHash = new \Phpass\Hash;
```

```php
<?php
// Customize hash adapter
$adapter = new \Phpass\Hash\Adapter\Pbkdf2(array (
  'iterationCountLog2' => 16 // 2^16 (65,536) iterations
));
$phpassHash = new \Phpass\Hash($adapter);
```

```php
<?php
// Customize hash adapter, with added HMAC hashing
$options = array (
  'adapter' => new \Phpass\Hash\Adapter\Pbkdf2(array (
    'iterationCountLog2' => 16 // 2^16 (65,536) iterations
  ),
  'hmacKey' => 'mys3cr3tk3y',
  'hmacAlgo' => 'sha512'
);
$phpassHash = new \Phpass\Hash($options);
```

```php
<?php
// Create and verify a password hash from any of the above configurations
$passwordHash = $phpassHash->hashPassword($password);
if ($phpassHash->checkPassword($password, $passwordHash)) {
  // Password verified...
}
```

Calculating password strength
-----------------------------

There are many different ways to calculate the relative strength of a given password, and this library supports a few of the most common. Each method returns a number which represents the estimated entropy for the given password. It's up to the developer to determine the minimum calculated entropy to accept. Combined with a sensible password policy, this can be a valuable tool in selecting strong passwords.

### Examples

```php
<?php
// Default configuration (NIST recommendations)
$phpassStrength = new \Phpass\Strength;

// Returns 30
$passwordEntropy = $phpassStrength->calculate('MySecretPassword');
```

```php
<?php
// Custom strength adapter (Wolfram algorithm)
$adapter = new \Phpass\Strength\Adapter\Wolfram;
$phpassStrength = new \Phpass\Strength($adapter);

// Returns 59
$passwordEntropy = $phpassStrength->calculate('MySecretPassword');
```