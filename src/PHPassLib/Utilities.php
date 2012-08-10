<?php
/**
 * PHP Password Library
 *
 * @package PHPassLib\Utilities
 * @author Ryan Chouinard <rchouinard@gmail.com>
 * @copyright Copyright (c) 2012, Ryan Chouinard
 * @license MIT License - http://www.opensource.org/licenses/mit-license.php
 * @version 3.0.0-dev
 */

namespace PHPassLib;

use PHPassLib\Exception\InvalidArgumentException;

/**
 * Misc. Utilities
 *
 * @package PHPassLib\Utilities
 * @author Ryan Chouinard <rchouinard@gmail.com>
 * @copyright Copyright (c) 2012, Ryan Chouinard
 * @license MIT License - http://www.opensource.org/licenses/mit-license.php
 */
class Utilities
{

    const CHARS_H64 = './0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz';

    /**
     * Generate a random string of raw bytes.
     *
     * @param integer $count Number of bytes to generate.
     * @return string Random string of raw bytes.
     */
    public static function genRandomBytes($count)
    {
        $count = (int) $count;

        // Try OpenSSL's random generator
        $output = '';
        if (function_exists('openssl_random_pseudo_bytes')) {
            $strongCrypto = false;
            // NOTE: The $strongCrypto argument here isn't telling OpenSSL to
            // generate (or not) cryptographically secure data. It's passed
            // by reference, and will be set to true or false after the
            // function call to indicate whether or not OpenSSL is confident
            // that the generated data can be used for cryptographic operations.
            $output = openssl_random_pseudo_bytes($count, $strongCrypto);
            if ($strongCrypto && strlen($output) == $count) {
                return $output;
            }
        }

        // Try creating an mcrypt IV
        $output = '';
        if (function_exists('mcrypt_create_iv')) {
            $output = mcrypt_create_iv($count, MCRYPT_DEV_URANDOM);
            if (strlen($output) == $count) {
                return $output;
            }
        }

        // Try reading from /dev/urandom, if present
        $output = '';
        if (is_readable('/dev/urandom') && ($fh = fopen('/dev/urandom', 'rb'))) {
            $output = fread($fh, $count);
            fclose($fh);
            if (strlen($output) == $count) {
                return $output;
            }
        }

        // Fall back to a locally generated "random" string as last resort
        $randomState = microtime();
        if (function_exists('getmypid')) {
            $randomState .= getmypid();
        }
        $output = '';
        for ($i = 0; $i < $count; $i += 16) {
            $randomState = md5(microtime() . $randomState);
            $output .= md5($randomState, true);
        }
        $output = substr($output, 0, $count);

        return $output;
    }

    /**
     * Encode a string with alternate base64 encoding.
     *
     * @param string $data String to encode.
     * @return string Encoded string.
     */
    public static function altBase64Encode($data)
    {
        return str_replace(array ('+', '=', "\n"), array ('.', '', ''), base64_encode($data));
    }

    /**
     * Decode a string which has been encoded with alternate base64 encoding.
     *
     * @param string $data String to decode.
     * @return string Decoded string.
     * @throws RuntimeException Throws an InvalidArgumentExceoption if
     *     invalid data is passed in.
     */
    public static function altBase64Decode($data)
    {
        $data = str_replace('.', '+', $data);
        switch (strlen($data) & 0x03) {
            case 0:
                return base64_decode($data);
            case 2:
                return base64_decode($data . '==');
            case 3:
                return base64_decode($data . '=');
            default:
                throw new InvalidArgumentException('Invalid data string');
        }
    }

    /**
     * Encode a string.
     *
     * @param string $bytes String to encode.
     * @param string $charset Optional character set used when encoding.
     * @return string Encoded string.
     */
    public static function encode64($bytes, $charset = null)
    {
        $count = strlen($bytes);
        if (!$charset) {
            $charset = self::CHARS_H64;
        }

        $output = '';
        $i = 0;
        do {
            $value = ord($bytes[$i++]);
            $output .= $charset[$value & 0x3f];
            if ($i < $count) {
                $value |= ord($bytes[$i]) << 0x08;
            }
            $output .= $charset[($value >> 0x06) & 0x3f];
            if ($i++ >= $count) {
                break;
            }
            if ($i < $count) {
                $value |= ord($bytes[$i]) << 0x10;
            }
            $output .= $charset[($value >> 0x0c) & 0x3f];
            if ($i++ >= $count) {
                break;
            }
            $output .= $charset[($value >> 0x12) & 0x3f];
        } while ($i < $count);

        return $output;
    }

    /**
     * Encode a 24-bit integer into a 4-byte string.
     *
     * @param integer $integer Integer to encode.
     * @return string Encoded string.
     * @throws InvalidArgumentException Throws an InvalidArgumentException if
     *     the supplied argument is not a 24-bit integer.
     */
    public static function encodeInt24($integer)
    {
        $integer = (int) $integer;
        $chars = self::CHARS_H64;

        if ($integer < 0x00 || $integer > 0xffffff) {
            throw new InvalidArgumentException('Integer out of range');
        }

        $string  = $chars[$integer & 0x3f];
        $string .= $chars[($integer >> 0x06) & 0x3f];
        $string .= $chars[($integer >> 0x0c) & 0x3f];
        $string .= $chars[($integer >> 0x12) & 0x3f];

        return $string;
    }

    /**
     * Decodes a 4-byte string into a 24-bit integer.
     *
     * @param string $string String to decode.
     * @return integer Decoded integer.
     * @throws InvalidArgumentException Throws an InvalidArgumentException if
     *     the supplied argument is not a valid encoded integer.
     */
    public static function decodeInt24($string)
    {
        $chars = self::CHARS_H64;

        if (!preg_match('/^[\.\/0-9A-Za-z]{4}$/', $string)) {
            throw new InvalidArgumentException('Invalid encoded string');
        }

        $integer  = strpos($chars, $string[0]);
        $integer += (strpos($chars, $string[1]) << 0x06);
        $integer += (strpos($chars, $string[2]) << 0x0c);
        $integer += (strpos($chars, $string[3]) << 0x12);

        return $integer;
    }

}
