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

namespace PHPassLib\Application;

use PHPassLib\Exception\RuntimeException;

/**
 * Application Context
 *
 * This class provides an interface for using the library within an large
 * application.
 *
 * <code>
 *     <?php
 *     $passlibContext = new PHPassLib\Application\Context;
 *     $passlibContext->addConfig('bcrypt'); // Use bcrypt with default options
 *
 *     $hash = $passlibContext->hash($password);
 *     if ($passlibContext->verify($password, $hash) {
 *         // ...
 *     }
 * </code>
 *
 * The context also allows us to check if a user's stored hash needs to be
 * updated to a newer version.
 *
 * <code>
 *     <?php
 *     $passlibContext = new PHPassLib\Application\Context;
 *
 *     // The first added config becomes the default
 *     // This is important for methods like hash() and needsUpdate()
 *     $passlibContext->addConfig('pbkdf2', array ('digest' => 'sha256'));
 *
 *     // Additional configs are supported by verify()
 *     $passlibContext->addConfig('bcrypt');
 *
 *     if ($passlibContext->verify($password, $hash)) {
 *         // needsUpdate() will return true if the provided hash fails to
 *         // match the default config in any way. This means bcrypt hashes as
 *         // well as PBKDF2 hashes which use a digest other than SHA-256.
 *         if ($passlibContext->needsUpdate($hash)) {
 *             // $newHash will be a PBKDF2 hash
 *             $newHash = $passlibContext->hash($password);
 *             // Store $newHash into the user object
 *         }
 *         // ...
 *     }
 * </code>
 *
 * @package PHPassLib\Hashes
 * @author Ryan Chouinard <rchouinard@gmail.com>
 * @copyright Copyright (c) 2012, Ryan Chouinard
 * @license MIT License - http://www.opensource.org/licenses/mit-license.php
 * @version 3.0.0-dev
 */
class Context
{

    /**
     * @var array
     */
    protected $classMap = array ();

    /**
     * @var array
     */
    protected $configs = array ();

    /**
     * @return void
     */
    public function __construct()
    {
        $defaultNamespace = 'PHPassLib\\Hash';
        $this
            ->registerClass('bcrypt', $defaultNamespace . '\\BCrypt')
            ->registerClass('bsdicrypt', $defaultNamespace . '\\BSDiCrypt')
            ->registerClass('descrypt', $defaultNamespace . '\\DESCrypt')
            ->registerClass('md5crypt', $defaultNamespace . '\\MD5Crypt')
            ->registerClass('pbkdf2', $defaultNamespace . '\\PBKDF2')
            ->registerClass('portable', $defaultNamespace . '\\Portable')
            ->registerClass('sha1crypt', $defaultNamespace . '\\SHA1Crypt')
            ->registerClass('sha256crypt', $defaultNamespace . '\\SHA256Crypt')
            ->registerClass('sha512crypt', $defaultNamespace . '\\SHA512Crypt');
    }

    /**
     * @param string $alias
     * @param string $classname
     * @return Context
     */
    public function registerClass($alias, $classname)
    {
        $this->classMap[strtolower($alias)] = $classname;
        return $this;
    }

    /**
     * @param string $algorithm
     * @param array $config
     * @return Context
     */
    public function addConfig($algorithm, array $config = array ())
    {
        $this->configs[$algorithm] = array (
            'classname' => $this->getClassFromAlias($algorithm),
            'config' => $config
        );
        return $this;
    }

    /**
     * @param string $password
     * @return string
     */
    public function hash($password)
    {
        $config = $this->getDefaultConfig();
        return call_user_func(array ($config['classname'], 'hash'), $password, $config['config']);
    }

    /**
     * @param string $password
     * @param string $hash
     * @return boolean
     */
    public function verify($password, $hash)
    {
        $config = $this->getConfigFromHash($hash);
        return call_user_func(array ($config['classname'], 'verify'), $password, $hash);
    }

    /**
     * @param string $hash
     * @return boolean
     */
    public function needsUpdate($hash)
    {
        $config = $this->getDefaultConfig();

        // Parse the supplied hash to extract the options
        $hashOptions = call_user_func(array ($config['classname'], 'parseConfig'), $hash);

        // Parse a config string from the default config
        $defaultConfigString = call_user_func(array ($config['classname'], 'genConfig'), $config['config']);
        $defaultOptions = call_user_func(array ($config['classname'], 'parseConfig'), $defaultConfigString);

        if (!$hashOptions || !$defaultOptions) {
            return true;
        }

        unset ($hashOptions['salt'], $defaultOptions['salt']);
        return (array () != array_diff_assoc($hashOptions, $defaultOptions));
    }

    /**
     * @return array
     * @throws RuntimeException
     */
    protected function getDefaultConfig()
    {
        if (count($this->configs) > 0) {
            reset($this->configs);
            return current($this->configs);
        }

        throw new RuntimeException('There are no configurations defined');
    }

    /**
     * @param string $hash
     * @return array
     * @throws RuntimeException
     */
    protected function getConfigFromHash($hash)
    {
        if (count($this->configs) < 1) {
            throw new RuntimeException('There are no configurations defined');
        }

        foreach ($this->configs as $config) {
            if (call_user_func(array ($config['classname'], 'parseConfig'), $hash) !== false) {
                return $config;
            }
        }

        throw new RuntimeException('Hash does not match any registered configuration');
    }

    /**
     * @param string $alias
     * @return string
     * @throws RuntimeException
     */
    protected function getClassFromAlias($alias)
    {
        $alias = strtolower($alias);
        if (!isset($this->classMap[$alias])) {
            throw new RuntimeException("Requested class alias '$alias' is not registered");
        }

        if (!class_exists($this->classMap[$alias], true)) {
            throw new RuntimeException("Failed loading class for alias '$alias'");
        }

        if (!in_array('PHPassLib\\Hash', class_implements($this->classMap[$alias]))) {
            throw new RuntimeException("Class alias '$alias' does not implement PHPass\Hash interface");
        }

        return $this->classMap[$alias];
    }

}
