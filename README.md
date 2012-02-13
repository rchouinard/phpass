PHPass: PHP Password Library
============================

What is PHPass?
---------------

PHPass is a PHP library designed to ease the tasks associated with working with passwords. It is capable of generating strong cryptographic hashes, verifying supplied passwords against those hashes, and calculating the relative strength of a given password.

Hashing passwords
-----------------

The library provides the ability to generate strong cryptographic hashes of user passwords using a variety of methods. Each method may be customized as needed, and may also be combined with HMAC hashing when using the base class.

### Examples

```php
<?php
// Default configuration (bcrypt adapter, 2^12 iterations)
$phpass = new Phpass;
$passwordHash = $phpass->hashPassword('MySecretPassword');

// Returns true
$isValid = $phpass->checkPassword('MySecretPassword', $passwordHash);
```

```php
<?php
// Custom hash adapter (PBKDF2 adapter, 2^16 iterations)
$hashAdapter = new Phpass\Hash\Pbkdf2(array (
  'iterationCountLog2' => 16
));
$phpass = new Phpass($hashAdapter);
$passwordHash = $phpass->hashPassword('MySecretPassword');

// Returns true
$isValid = $phpass->checkPassword('MySecretPassword', $passwordHash);
```

Calculating password strength
-----------------------------

There are many different ways to calculate the relative strength of a given password, and this library supports a few of the most common. Each method returns a number which represents the estimated entropy for the given password. It's up to the developer to determine the minimum calculated entropy to accept. Combined with a sensible password policy, this can be a valuable tool in selecting strong passwords.

### Examples

```php
<?php
// Default configuration (NIST recommendations)
$phpass = new Phpass;

// Returns 30
$passwordEntropy = $phpass->calculateEntropy('MySecretPassword');
```

```php
<?php
// Custom strength adapter (Wolfram algorithm)
$strengthAdapter = new Phpass\Strength\Wolfram;
$phpass = new Phpass($strengthAdapter);

// Returns 59
$passwordEntropy = $phpass->calculateEntropy('MySecretPassword');
```