<?php
/**
 * PHP Password Library
 *
 * @package PHPassLib\Hashes
 * @author Ryan Chouinard <rchouinard@gmail.com>
 * @copyright Copyright (c) 2012, Ryan Chouinard
 * @license MIT License - http://www.opensource.org/licenses/mit-license.php
 * @version 3.0.0-dev
 */

namespace PHPassLib;

/**
 *
 */
abstract class Hash
{

    abstract public static function genConfig(Array $config);

    abstract public static function genHash($password, $config);

    abstract public static function hash($password, $config);

    abstract public static function verify($password, $hash);

}