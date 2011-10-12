PHPass: Portable PHP password hashing framework
===============================================

What is PHPass?
---------------

PHPass is a library useful in creating secure password hashes suitable for storage in a database.

This library is a reimplementation of the [PasswordHash](http://openwall.com/phpass/) class from Openwall. It uses the same underlying methods as the original class, so the output is 100% compatible. The goal is to create a library which is more flexible than the original.

How does it work?
-----------------

Multiple methods of generating secure password hashes are implemented in the library. The quick version is that it uses [bcrypt](http://en.wikipedia.org/wiki/Bcrypt), and may be combined with [HMAC](http://en.wikipedia.org/wiki/Hmac). Support for the popular [PBKDF2](http://en.wikipedia.org/wiki/PBKDF2) with HMAC-SHA2 hashing is also provided. 

The longer version is that the library may be configured to use a variety of adapters to generate the hash string. While most applications will want to use the Blowfish adapter, it is also possible to generate Extended DES or MD5-based salted passwords (compatible with phpBB). All included adapters support [key stretching](http://en.wikipedia.org/wiki/Key_stretching), and will generate random, unique salt values. Developers may also create their own adapters for custom hashing methods.

As mentioned previously, it is possible, and very easy, to use HMAC + bcrypt using this library. By passing in the options 'hmacKey' and (optionally) 'hmacAlgo', the password string will be hashed using the chosen HMAC algorithm and key prior to being passed to bcrypt. The benefits of this are outlined in [Mozilla's Web Application Security wiki](https://wiki.mozilla.org/WebAppSec/Secure_Coding_Guidelines#Password_Storage).

Requirements
------------

You will need to be using PHP 5.3+ in order to use this library. It should not have any other external dependencies.

Installation
------------

Installation can be done via PEAR.

```bash
pear channel-discover rchouinard.github.com/pear
pear install rych/PHPass-1.0.0
```

Alternatively, you may choose to clone the git repository and add the library folder to your include path.

```bash
git clone git://github.com/rchouinard/phpass.git
```

Quick Start
-----------

The main class is Phpass, and uses two main methods: `hashPassword()` and `checkPassword()`, shown in the example below. By default, the class will create an instance of the blowfish adapter if an adapter is not otherwise given.

```php
<?php
$phpass = new Phpass;

// Alternative, if using HMAC
//$phpass = new Phpass(array ('hmacKey' => 'MySuperSecretKey'));

// Returns a hash which can be stored in a database
$hash = $phpass->hashPassword($myPassword);

// Checks a password against a stored hash, probably from a database
if ($phpass->checkPassword($myPassword, $hash) {
    echo 'Password matches!';
} else {
    echo 'Password does not match!';
}
```

Configuration
-------------

The Phpass class can be given either a pre-configured Adapter instance, or an array of configuration options. The following configuration options are supported.

<dt>adapter</dt>
  <dd>May be either a concrete instance of \Phpass\Adapter or an array. The adapter array should contain at least a 'type' key with the name of the desired adapter, and optionally an 'options' key containing an array of options to pass to the adapter. See \Phpass\Adapter\Base::setOptions() for details.</dd>
<dt>hmacKey</dt>
  <dd>Optional; Application-wide key used to generate HMAC hashes. If omitted, HMAC hashing is disabled.</dd>
<dt>hmacAlgo</dt>
  <dd>Optional; String naming one of the many hashing algorithms available. A full list may be retrieved from the hash_algos() function. Defaults to sha256.</dd>

### Passing an adapter to the constructor

```php
<?php
$adapter = new Phpass\Adapter\Portable;
$phpass = new Phpass($adapter);
```

### Passing an array of options to the constructor

```php
<?php
$options = array (
    'adapter' => array (
        'type' => 'extdes', // One of blowfish, extdes, or portable
        'options' => array ( // Options array passed to adapter constructor
            'iterationCountLog2' => 12
        )
    )
);
$phpass = new Phpass($options);
```

Adapters
--------

The library includes three adapters which wrap different cipher methods.

#### Common Options

<dt>iterationCountLog2</dt>
  <dd>_Integer_; This number is the base-2 logarithm representation of the iteration count used for key stretching. The final iteration count can be calculated with 2^x, so a value of 8 will yield 2^8, or 256, iterations. A value of 12 will yield 2^12, or 4,096 iterations.</dd>

### Blowfish

This adapter uses the blowfish cipher to create one-way hashes.

```php
<?php
$adapterOptions = array (
    'iterationCountLog2' => 8
);

$adapter = new Phpass\Adapter\Blowfish($adapterOptions);

// $2a$08$xZQ8G2a1XLjxr14Rc0zOP.
$salt = $adapter->genSalt();

// $2a$08$xZQ8G2a1XLjxr14Rc0zOP.X8atMFBx8J6EaFhniNvujgcqs17TgGC
$hash = $adapter->crypt('password', $salt);
```

### Extended DES

This adapter uses the extended DES cipher to create one-way hashes.

```php
<?php
$adapterOptions = array (
    'iterationCountLog2' => 8
);

$adapter = new Phpass\Adapter\ExtDes($adapterOptions);

// _zzD.d84Z
$salt = $adapter->genSalt();

// _zzD.d84ZhoAfE8.PYgQ
$hash = $adapter->crypt('password', $salt);
```

### PBKDF2

This adapter uses PBKDF2 HMAC-SHA2 in order to create one-way hashes.

```php
<?php
$adapterOptions = array (
    'iterationCountLog2' => 12
);

$adapter = new Phpass\Adapter\Pbkdf2($adapterOptions);

// $p5v2$AY8J8OdvL$
$salt = $adapter->genSalt();

// $p5v2$AY8J8OdvL$.wQWX6hD9T6ERlpYY8vb12jYueQVW5Ai
$hash = $adapter->crypt('password', $salt);
```

### Portable

This adapter uses a custom cipher to create one-way hashes. It is compatible with phpBB passwords.

```php
<?php
$adapterOptions = array (
    'iterationCountLog2' => 8
);

$adapter = new Phpass\Adapter\Portable($adapterOptions);

// $P$BItJrOG/2
$salt = $adapter->genSalt();

// $P$BItJrOG/2OwpzlDFMRNPR8vUIlcBbi/
$hash = $adapter->crypt('password', $salt);
```

License
-------

Since US law does not allow directly publishing works to the public domain, I'm licensing this library under the terms of the [MIT license](http://www.opensource.org/licenses/mit-license.html).