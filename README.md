PHP Password Library
====================

The PHP Password Library is designed to ease the tasks associated with working
with passwords in PHP. It is capable of generating strong cryptographic password
hashes, verifying supplied password strings against those hashes, and
calculating the strength of a password string using various algorithms.

This project was inspired by [Openwall's portable hashing library for PHP](http://openwall.com/phpass/)
and [PassLib for Python](http://packages.python.org/passlib/).


Features
--------

 * Create and verify secure password hashes with only a few lines of code.
 * Supports bcrypt and PBKDF2 out of the box.
 * Easily extend to support additional hashing methods.
 * Additional password strength component based on well-known algorithms.
 * Follows the [PSR-0](https://github.com/php-fig/fig-standards/blob/master/accepted/PSR-0.md)
   standard for autoloader compatibility.


Installation via [Composer](http://getcomposer.org/)
------------

 * Install Composer to your project root:
    ```bash
    curl -sS https://getcomposer.org/installer | php
    ```

 * Add a `composer.json` file to your project:
    ```json
    {
      "require" {
        "rych/phpass": "dev-develop"
      }
    }
    ```

 * Run the Composer installer:
    ```bash
    php composer.phar install
    ```


Usage
-----


### Hashing passwords

The library provides the ability to generate strong cryptographic hashes of user
passwords using a variety of methods. Each method may be customized as needed,
and may also be combined with HMAC hashing when using the base class.


#### Examples

Use the default bcrypt adapter:

```php
<?php
// Default configuration - bcrypt adapter, 2^12 (4,096) iterations
$phpassHash = new \PHPassLib\Hash;
```

Use the PBKDF2 adapter:

```php
<?php
// Customize hash adapter - PBKDF2 adapter, 15,000 iterations
$adapter = new \PHPassLib\Hash\Adapter\Pbkdf2(array (
    'iterationCount' => 15000
));
$phpassHash = new \PHPassLib\Hash($adapter);
```

Create and verify a password hash:

```php
<?php
// Create and verify a password hash from any of the above configurations
$passwordHash = $phpassHash->hashPassword($password);
if ($phpassHash->checkPassword($password, $passwordHash)) {
    // Password matches...
} else {
    // Password doesn't match...
}
```


### Calculating password strength

There are many different ways to calculate the relative strength of a given
password, and this library supports a few of the most common. Each method
returns a number which represents the estimated entropy for the given password.
It's up to the developer to determine the minimum calculated entropy to accept.
Combined with a sensible password policy, this can be a valuable tool in
selecting strong passwords.


#### Examples

Calculate a password's entropy using [NIST recommendations](http://en.wikipedia.org/wiki/Password_strength#NIST_Special_Publication_800-63):

```php
<?php
// Default configuration (NIST recommendations)
$phpassStrength = new \PHPassLib\Strength;

// Returns 30
$passwordEntropy = $phpassStrength->calculate('MySecretPassword');
```

Calculate a password's entropy using [Wolfram Alpha's algorithm](http://www.wolframalpha.com/input/?i=password+strength+for+qwerty2345#):

```php
<?php
// Custom strength adapter (Wolfram algorithm)
$adapter = new \PHPassLib\Strength\Adapter\Wolfram;
$phpassStrength = new \PHPassLib\Strength($adapter);

// Returns 59
$passwordEntropy = $phpassStrength->calculate('MySecretPassword');
```
