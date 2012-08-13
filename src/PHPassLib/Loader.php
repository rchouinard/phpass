<?php
/**
 * PHP Password Library
 *
 * @package PHPassLib\Loaders
 * @author Ryan Chouinard <rchouinard@gmail.com>
 * @copyright Copyright (c) 2012, Ryan Chouinard
 * @license MIT License - http://www.opensource.org/licenses/mit-license.php
 * @version 3.0.0-dev
 */

namespace PHPassLib;

/**
 * Class Loader
 *
 * This class provides methods for loading library resources conforming to
 * PSR-0 standards. Only classes in the PHPassLib namespace will be loaded by
 * Loader::load().
 *
 * @package PHPassLib\Loaders
 * @author Ryan Chouinard <rchouinard@gmail.com>
 * @copyright Copyright (c) 2012, Ryan Chouinard
 * @license MIT License - http://www.opensource.org/licenses/mit-license.php
 */
class Loader
{

    /**
     * Load a library class.
     *
     * Performs checks to make sure only local library classes are loaded, and
     * the class file exists within the library path.
     *
     * @param string $class The fully qualified class name to load.
     * @return void
     */
    public static function load($class)
    {
        if (substr($class, 0, 9) !== 'PHPassLib') {
            return;
        }

        $libraryRoot = dirname(__DIR__);
        $file = str_replace('\\', DIRECTORY_SEPARATOR, $class) . '.php';
        $file = realpath($libraryRoot . DIRECTORY_SEPARATOR . $file);
        if (substr($file, 0, strlen($libraryRoot)) == $libraryRoot) {
            if (is_readable($file)) {
                include $file;
            }
        }
    }

    /**
     * Register an autoloader for the library.
     *
     * @return boolean Returns true on success, false on failure.
     */
    public static function registerAutoloader()
    {
        return spl_autoload_register(array ('PHPassLib\\Loader', 'load'));
    }

}
