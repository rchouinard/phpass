PHP Password Library
====================

Easy, secure password management for PHP

Overview
--------

PHPassLib is a password utility library for PHP 5.3+. The goal of this project
is to make working with passwords as simple as possible. To that end the
library eases the creation and verification of multiple password formats,
including but not limited to bcrypt and pbkdf2.

Quick Start
-----------

=== Hashing Passwords ===

The latest version of this library has been revamped based on user feedback.
The hashing adapters are now far easier to use.

```php
<?php
use PHPassLib\Hash\BCrypt;

// Calculate a hash based on the string "password"
$hash = BCrypt::hash('password');

// Check a password against a hash
if (BCrypt::verify('password', $hash) {
    // Password matches
} else {
    // Password does not match
}
```

Each hashing module is preset with sane defaults which are very easy to
override if required. The available options vary from module to module, so be
sure to check the documentation.

```php
<?php
use PHPassLib\Hash\BCrypt;

// Calculate a hash using a cost factor of 16 instead of the default of 12
$hash = BCrypt::hash(
    'password', // Password string to hash
    array ( // Array of module options
        'rounds' => 16,
    )
);
```