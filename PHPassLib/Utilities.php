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
 *
 */
class Utilities
{

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
     * @param string $data String to be encoded.
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

}