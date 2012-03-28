<?php
/**
 * PHP Password Library
 *
 * Convenience file for bootstrapping the PHPass library.
 *
 * @package PHPass
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass Project at GitHub
 */

require_once 'Phpass/Loader.php';
\Phpass\Loader::registerAutoloader();