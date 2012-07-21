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

namespace PHPassLib\Hash;

use PHPassLib\Hash;
use PHPassLib\Utilities;
use PHPassLib\Exception\InvalidArgumentException;

/**
 * PHPass Portable Module
 *
 * @package PHPassLib\Hashes
 * @author Ryan Chouinard <rchouinard@gmail.com>
 * @copyright Copyright (c) 2012, Ryan Chouinard
 * @license MIT License - http://www.opensource.org/licenses/mit-license.php
 */
class Portable implements Hash
{

    const IDENT_PHPASS = 'P';
    const IDENT_PHPBB = 'H';

    /**
     * Generate a config string suitable for use with module hashes.
     *
     * @param array $config Array of configuration options.
     * @return string Configuration string.
     * @throws InvalidArgumentException Throws an InvalidArgumentException if
     *     any passed-in configuration options are invalid.
     */
    public static function genConfig(array $config = array ())
    {
        $defaults = array (
            'ident' => self::IDENT_PHPASS,
            'rounds' => 16,
            'salt' => Utilities::encode64(Utilities::genRandomBytes(6)),
        );
        $config = array_merge($defaults, array_change_key_case($config, CASE_LOWER));

        $string = '*1';
        try {
            self::validateOptions($config);
            $charset = Utilities::CHARS_H64;
            $string = sprintf('$%s$%s%s', $config['ident'], $charset[(int) $config['rounds']], $config['salt']);
        } catch (InvalidArgumentException $e) {
            trigger_error($e->getMessage(), E_USER_WARNING);
        }

        return $string;
    }

    /**
     * Parse a config string and extract the options used to build it.
     *
     * @param string $config Configuration string.
     * @return array Options array or false on failure.
     */
    public static function parseConfig($config)
    {
        $options = false;
        $matches = array ();
        if (preg_match('/^\$(P|H)\$([5-9A-S]{1})([\.\/0-9A-Za-z]{8})/', $config, $matches)) {
            $options = array (
                'ident' => $matches[1],
                'rounds' => strpos(Utilities::CHARS_H64, $config[3]),
                'salt' => $matches[3],
            );
        }

        return $options;
    }

    /**
     * Generate a hash using a pre-defined config string.
     *
     * @param string $password Password string.
     * @param string $config Configuration string.
     * @return string Returns the hash string on success. On failure, one of
     *     *0 or *1 is returned.
     */
    public static function genHash($password, $config)
    {
        $output = '*0';
        $config = substr($config, 0, 12);

        if (preg_match('/^\$(?:P|H)\$[5-9A-S]{1}[\.\/0-9A-Za-z]{8}$/', $config)) {
            $charset = Utilities::CHARS_H64;
            $rounds = (1 << strpos($charset, $config[3]));
            $checksum = md5(substr($config, 4, 8) . $password, true);
            do {
                $checksum = md5($checksum . $password, true);
            } while (--$rounds);
            $output = $config . Utilities::encode64($checksum);
        }

        if (!preg_match('/^\$(?:P|H)\$[5-9A-S]{1}[\.\/0-9A-Za-z]{30}$/', $output)) {
            $output = ($config == '*0') ? '*1' : '*0';
        }

        return $output;
    }

    /**
     * Generate a hash using either a pre-defined config string or an array.
     *
     * @see Hash::genConfig()
     * @see Hash::genHash()
     * @param string $password Password string.
     * @param string|array $config Optional config string or array of options.
     * @return string Returns the hash string on success. On failure, one of
     *     *0 or *1 is returned.
     */
    public static function hash($password, $config = array ())
    {
        if (is_array($config)) {
            $config = self::genConfig($config);
        }

        return self::genHash($password, $config);
    }

    /**
     * Verify a password against a hash string.
     *
     * @param string $password Password string.
     * @param string $hash Hash string.
     * @return boolean Returns true if the password matches, false otherwise.
     */
    public static function verify($password, $hash)
    {
        return ($hash === self::hash($password, $hash));
    }

    /**
     * Validate a set of module options.
     *
     * @param array $options Associative array of options.
     * @return boolean Returns true if all options are valid.
     * @throws InvalidArgumentException Throws an InvalidArgumentException
     *     if an invalid option value is encountered.
     */
    protected static function validateOptions(array $options)
    {
        $options = array_change_key_case($options, CASE_LOWER);
        foreach ($options as $option => $value) switch ($option) {

            case 'ident':
                $idents = array (self::IDENT_PHPASS, self::IDENT_PHPBB);
                if (!in_array($value, $idents)) {
                    throw new InvalidArgumentException('Identifier must be one of "P" or "H".');
                }
                break;

            case 'rounds':
                if ($value < 7 || $value > 30) {
                    throw new InvalidArgumentException('Rounds must be a number in the range 7 - 30.');
                }
                break;

            case 'salt':
                if (!preg_match('/^[\.\/0-9A-Za-z]{8}$/', $value)) {
                    throw new InvalidArgumentException('Salt must be a string matching the regex pattern /[./0-9A-Za-z]{8}/.');
                }
                break;

            default:
                break;

        }

        return true;
    }

}