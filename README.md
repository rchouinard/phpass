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

Quick Start
-----------

### Hashing Passwords ###

Each hashing module is preset with sane defaults which are very easy to
override if required. The available options vary from module to module, so be
sure to check the documentation.

```php
<?php
use PHPassLib\Hash\BCrypt;

// Calculate a hash
$hash = BCrypt::hash($password);

// Check a password against a hash
if (BCrypt::verify($password, $hash)) {
    // Password is valid
}
```

### Contexts ###

Application contexts allow you to configure one or more modules for your
application in a central location, say in your bootstrap process.

The example below creates a context using the BCrypt adapter with a custom
configuration. The context can then be passed to other objects to provide
consistent bcrypt hashes configured in one place.

```php
<?php
use PHPassLib\Application\Context;

$passlibContext = new Context;
$passlibContext->addConfig('BCrypt', array (
    'ident' => '2y',
    'rounds' => 16,
));

// Hash a password
$hash = $passlibContext->hash($password);

// Verify a password
if ($passlibContext->verify($password, $hash)) {
    // ...
}
```

A single context can support multiple configurations, with a couple
limitations:

 1. The first configuration added to the context is the default, and will
    be used for all `hash()` operations.
 2. Only one configuration per hash module is supported.

So what good is this functionality? Each added configuration allows the context
to verify hashes for that configuration. Adding a configuration for PBKDF2 and
BCrypt allows the context's `verify()` method to verify either PBKDF2 or BCrypt
hashes. Additionally, you can use the `needsUpdate()` method to migrate between
hashes. The example below shows this usage.

```php
<?php
use PHPassLib\Application\Context;

$passlibContext = new Context;
$passlibContext
    ->addConfig('PBKDF2', array ('digest' => 'sha1')) // PBKDF2 becomes the default
    ->addConfig('BCrypt');

// Will verify both PBKDF2 and bcrypt hashes
if ($passlibContext->verify($password, $hash)) {
    // If the user's hash is a bcrypt hash, this returns true
    if ($passlibContext->needsUpdate($hash)) {
        // Will create a PBKDF2-SHA1 hash, since that's the default
        $newHash = $passlibContext->hash($password);
        // Store the new hash with the user record
        // ...
    }
    // ...
}
```

The `needsUpdate()` method will identify any configured hash which does not
match the default configuration. This means that updating the parameters within
the same module is easy as well.

If your user's hash was created with BCrypt using 12 rounds, and the default
configuration is BCrypt with 16 rounds, `needsUpdate()` will still return
true.