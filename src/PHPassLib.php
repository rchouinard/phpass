<?php
/**
 * PHP Password Library
 *
 * This file provides a stub for registering the library autoloader.
 *
 * <code>
 * &lt;?php
 * require 'PHPassLib.php';
 * $hash = PHPassLib\Hash\BCrypt::hash($password);
 * </code>
 *
 * @package PHPassLib
 * @author Ryan Chouinard <rchouinard@gmail.com>
 * @copyright Copyright (c) 2012, Ryan Chouinard
 * @license MIT License - http://www.opensource.org/licenses/mit-license.php
 * @version 3.0.0-dev
 */

use PHPassLib\Loader;

require_once 'PHPassLib/Loader.php';
Loader::registerAutoloader();