PHP Password Library
====================

Easy, secure password management for PHP

Overview
--------

PHPassLib is a password utility library for PHP 5.3+. The goal of this project
is to make working with passwords as simple as possible. To that end the
library eases the creation and verification of multiple password formats,
including but not limited to bcrypt and pbkdf2.

### Supported Hashes ###

The library supports the following hash schemes:

 - BCrypt
 - BSDi / Extended DES Crypt
 - DES Crypt
 - MD5 Crypt
 - PBKDF2-SHA1/256/512 (compatible with [Python's PassLib](http://packages.python.org/passlib/))
 - Openwall's Portable Hash
 - SHA-1 Crypt
 - SHA-256 Crypt
 - SHA-512 Crypt
 - Plus more on the way!

Quick Start
-----------

### Hashing Passwords ###

Each hashing module is preset with sane defaults which are very easy to
override if required. The available options vary from module to module, so be
sure to check the documentation.

```php
<?php
use PHPassLib\Hash\BCrypt;

// Calculate a hash from "password"
$hash = BCrypt::hash('password');

// Check a password against a hash
if (BCrypt::verify('password', $hash)) {
    // Password is valid
}
```

Hashing API
-----------

All hashing modules implement a static API exposing the methods `genConfig()`,
`genHash()`, `hash()`, and `verify()`.

`genConfig()` accepts an associative array of module options and returns a
configuration string which can then be used with `genHash()` or compatible
`crypt()` implementations. Each module accepts different options, so be sure
to check the documentation of the module you wish to use.

```php
<?php
use PHPassLib\Hash\BCrypt;

// Example: $2a$12$PZjBmya2CRrOw/D3cXIbgO
$configString = BCrypt::genConfig();

// Example: $2y$08$nDTnXZCvtNfOaSA.mKXbJu
$configString = BCrypt::genConfig(array (
    'ident' => '2y',
    'rounds' => 8,
));
```

`genHash()` takes a password string and a configuration string from
`genConfig()` and returns a hash string containing the calculated password
checksum.

```php
<?php
use PHPassLib\Hash\BCrypt;

// Example: $2a$12$PZjBmya2CRrOw/D3cXIbgO626rW0s2xvjAYd2ixJqSC523DltPZYS
$hashString = BCrypt::genHash('password', '$2a$12$PZjBmya2CRrOw/D3cXIbgO');
```

`hash()` is a shortcut method which accepts a password string and either an
associative array of options or a configuration string and returns a hash
string containing the calculated password checksum.

```php
<?php
use PHPassLib\Hash\BCrypt;

// Example: $2a$12$PZjBmya2CRrOw/D3cXIbgO626rW0s2xvjAYd2ixJqSC523DltPZYS
$hashString = BCrypt::hash('password');

// Example: $2y$08$nDTnXZCvtNfOaSA.mKXbJuhEdoMn2zAmiFydtBqf5wuG7iZYwuWSK
$hashString = BCrypt::hash('password', '$2y$08$nDTnXZCvtNfOaSA.mKXbJu');

// Example: $2y$12$vveVMOHi8f2iWjuSNNQcgupCnorU6MPdTlrFeDUJxv6S8UjzWa8B.
$hashString = BCrypt::hash('password', array (
    'ident' => '2y',
));
```

`verify()` takes a password string and a hash string. A new hash string is
calculated from the password string using the stored configuration in the
supplied hash string. If the resulting hash string matches the supplied hash
string, true is returned. False is returned otherwise.

```php
<?php
use PHPassLib\Hash\BCrypt;

// Example: true
$match = BCrypt::verify('password', '$2a$12$PZjBmya2CRrOw/D3cXIbgO626rW0s2xvjAYd2ixJqSC523DltPZYS');

// Example: false
$match = BCrypt::verify('wordpass', '$2a$12$PZjBmya2CRrOw/D3cXIbgO626rW0s2xvjAYd2ixJqSC523DltPZYS');
```