PHPass: Portable PHP password hashing framework
-----------------------------------------------

This library is a reimplementation of the [PHPass](http://openwall.com/phpass/) class. The output is 100% compatible with the original, the library is simply updated to use more PHP5 conventions.

Usage is simple:

```php
<?php

// Hash methods are seperated out to adapters.
// This array configured the Blowfish adapter.
$options = array (
    'adapter' => array (
        'adapter' => 'blowfish',
        'options' => array (
            'iterationCountLog2' => 12
        )
    )
);

// Instantiate the library with the above config.
$phpass = new Phpass($options);

// Create a password hash.
$hash = $phpass->hashPassword('password');

// Verify a hash.
$success = $phpass->checkPassword('password', $hash);
```

In keeping with the original project, this library is entered into the public domain.