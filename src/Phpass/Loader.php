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
    public static function load($class)
    {
        if (stripos($class, 'Phpass') === 0) {
            $file = str_replace('\\', '/', $class);

            if (file_exists(dirname(__FILE__) . '/../' . $file . '.php')) {
                require_once(dirname(__FILE__) . '/../' . $file . '.php');
            }
        }
    }

    /**
     * Register an autoloader for the library.
     *
     * @return boolean
     *   Returns true on success, false on failure.
     */
    public static function registerAutoloader()
    {
        return spl_autoload_register(array ('Phpass\\Loader', 'load'));
    }

}
