PHPass: Portable PHP password hashing framework
===============================================

This library is a reimplementation of the [PHPass](http://openwall.com/phpass/) class. The output is 100% compatible with the original, the library is simply updated to use more PHP5 conventions.

The hashing methods used by the library have been broken out into adapters.

 * Blowfish (blowfish)
 * Extended DES (extdes)
 * Portable (portable)

Usage
-----

The basic library can be used in the same way as the original PasswordHash class.

```php
<?php

// Use the class with an iteration count of 12, using the Blowfish adapter.
// If the blowfish is not available, the class will fall back to Portable.
$phpass = new Phpass(12, false);

// Use the class with an iteration count of 12, using the Portable adapter.
$phpass = new Phpass(12, true);

// Hash a password.
$hash = $phpass->hashPassword('password');

// Check that a password matches a hash.
if ($phpass->checkPassword('password', $hash)) {
    echo "It's good!";
}
```

For more control over the library, it can be instantiated with an options array.

```php
<?php

$options = array (
    'allowFallback' => false, // If the adapter isn't supported, use Portable.
    'adapter' => array (
        'adapter' => 'extdes', // Options are blowfish, extdes, or portable.
        'options' => array (
            'iterationCountLog2' => 12 // Options may vary by adapter, although
                                       // currently all only support
                                       // iterationCountLog2
        )
    )
);

$phpass = new Phpass($options);
```

Adapters
--------

Adapters may be used outside of the main Phpass class very easily. The main methods in these adapters are `genSalt()` and `crypt()`. Creating new adapters is very easy by implementing Phpass_AdapterInterface or extending Phpass_Adapter. Using custom adapters with the Phpass class is very easy.

```php
<?php

// Use a custom adapter using the Phpass options.
$options = array (
    'adapter' => array (
        'adapter' => 'My_Custom_Adapter', // Use the full class name!
        'options' => array (
            'myOption' => true
        )
    )
);

$phpass = new Phpass($options);

// Use a custom adapter by passing it to Phpass via setAdapter().
$options = array (
    'myOption' => true
);
$myAdapter = new My_Custom_Adapter($options);

$phpass = new Phpass;
$phpass->setAdapter($myAdapter);
```

License
-------

In keeping with the original project, this library is entered into the public domain.