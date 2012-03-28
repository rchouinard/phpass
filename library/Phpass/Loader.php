<?php
/**
 * PHP Password Library
 *
 * @package PHPass
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass Project at GitHub
 */

/**
 * @namespace
 */
namespace Phpass;

/**
 * Class loader
 *
 * This class provides static methods for loading and autoloading library
 * classes. The most common use for this class is to simply call
 * \Phpass\Loader::registerAutoloader() before using any library components.
 *
 *     <?php
 *     require_once 'Phpass/Loader.php';
 *     \Phpass\Loader::registerAutoloader();
 *     
 *     $phpassHash = new \Phpass\Hash;
 *     // ...
 *
 * @package PHPass
 * @category Cryptography
 * @author Ryan Chouinard <rchouinard at gmail.com>
 * @license http://www.opensource.org/licenses/mit-license.html MIT License
 * @link https://github.com/rchouinard/phpass Project at GitHub
 */
class Loader
{

    /**
     * Load a library class.
     *
     * Performs checks to make sure only local library classes are loaded, and
     * the class file exists within the library path.
     *
     * @param string $class
     *   The fully qualified class name to load.
     * @return void
     */
    static public function load($class)
    {
        if (substr($class, 0, 6) !== 'Phpass') {
            return;
        }

        $libraryRoot = realpath(__DIR__ . '/../');
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
     * @return boolean
     *   Returns true on success, false on failure.
     */
    static public function registerAutoloader()
    {
        return spl_autoload_register(array ('Phpass\\Loader', 'load'));
    }

}