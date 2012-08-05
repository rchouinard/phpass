<?php
/**
 * PHP Password Library
 *
 * Convenience file for bootstrapping the library.
 *
 * @package PHPass
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass Project at GitHub
 */

use Phpass\Loader;

require_once 'Phpass/Loader.php';
Loader::registerAutoloader();
