<?php
/**
 * PHP Password Library
 *
 * @package PHPassLib\Tests
 * @author Ryan Chouinard <rchouinard@gmail.com>
 * @copyright Copyright (c) 2012, Ryan Chouinard
 * @license MIT License - http://www.opensource.org/licenses/mit-license.php
 * @version 3.0.0-dev
 */

namespace PHPassLib\Test\Hash;

use PHPassLib\Hash\SHA512Crypt;

/**
 * SHA-512 Crypt Tests
 *
 * @package PHPassLib\Tests
 * @author Ryan Chouinard <rchouinard@gmail.com>
 * @copyright Copyright (c) 2012, Ryan Chouinard
 * @license MIT License - http://www.opensource.org/licenses/mit-license.php
 */
class SHA512CryptTest extends \PHPUnit_Framework_TestCase
{

    /**
     * Provide valid test vectors.
     *
     * @return array
     */
    public function validTestVectorProvider()
    {
        $vectors = array (
            // http://www.akkadia.org/drepper/SHA-crypt.txt
            array ("Hello world!", '$6$saltstring$svn8UoSVapNtMuq1ukKS4tPQd8iKwSMHWjl/O817G3uBnIFNjnQJuesI68u4OTLiBFdcbYEdFCoEOfaS35inz1'),
            array ("Hello world!", '$6$rounds=10000$saltstringsaltst$OW1/O6BYHV6BcXZu8QVeXbDWra3Oeqh0sbHbbMCVNSnCM/UrjmM0Dp8vOuZeHBy/YTBmSK6H9qs/y3RnOaw5v.'),
            array ("This is just a test", '$6$rounds=5000$toolongsaltstrin$lQ8jolhgVRVhY4b5pZKaysCLi0QBxGoNeKQzQ3glMhwllF7oGDZxUhx1yxdYcz/e1JSbq3y6JMxxl8audkUEm0'),
            array ("a very much longer text to encrypt.  This one even stretches over morethan one line.", '$6$rounds=1400$anotherlongsalts$POfYwTEok97VWcjxIiSOjiykti.o/pQs.wPvMxQ6Fm7I6IoYN3CmLs66x9t0oSwbtEW7o7UmJEiDwGqd8p4ur1'),
            array ("we have a short salt string but not a short password", '$6$rounds=77777$short$WuQyW2YR.hBNpjjRhpYD/ifIw05xdfeEyQoMxIXbkvr0gge1a1x3yRULJ5CCaUeOxFmtlcGZelFl5CxtgfiAc0'),
            array ("a short string", '$6$rounds=123456$asaltof16chars..$BtCwjqMJGx5hrJhZywWvt0RLE8uZ4oPwcelCjmw2kSYu.Ec6ycULevoBK25fs2xXgMNrCzIMVcgEJAstJeonj1'),
            array ("the minimum number is still observed", '$6$rounds=1000$roundstoolow$kUMsbe306n21p9R.FRkW3IGn.S9NPN0x50YhH1xhLsPuWGsUSklZt58jaTfF4ZEQpyUNGc0dqbpBYYBaHHrsX.'),
        );

        return $vectors;
    }

    /**
     * Provide invalid test vectors.
     *
     * @return array
     */
    public function invalidTestVectorProvider()
    {
        $vectors = array (
            array ("", '*0', '*1'),
            array ("", '*1', '*0'),
        );

        return $vectors;
    }

    /**
     * Verify that the class produces correct results with valid test vectors.
     *
     * @test
     * @dataProvider validTestVectorProvider
     * @param string $password
     * @param string $hash
     */
    public function validTestVectorsProduceExpectedResults($password, $hash)
    {
        $this->assertEquals($hash, SHA512Crypt::hash($password, $hash));
        $this->assertTrue(SHA512Crypt::verify($password, $hash));
    }

    /**
     * Verify that the class produces correct results with invalid test vectors.
     *
     * @test
     * @dataProvider invalidTestVectorProvider
     * @param string $password
     * @param string $hash
     */
    public function invalidTestVectorsProduceExpectedResults($password, $hash, $errorString)
    {
        $this->assertEquals($errorString, SHA512Crypt::hash($password, $hash));
        $this->assertFalse(SHA512Crypt::verify($password, $hash));
    }

    /**
     * @test
     */
    public function genconfigAndParseconfigProduceMatchingResults()
    {
        $options = array (
            'rounds' => 5000,
            'salt' => 'CCCCCCC.',
        );
        $config = SHA512Crypt::genConfig($options);

        $this->assertEquals('$6$CCCCCCC.', $config);
        $this->assertSame($options, SHA512Crypt::parseConfig($config));

        $options = array (
            'rounds' => 8000,
            'salt' => 'CCCCCCC.',
        );
        $config = SHA512Crypt::genConfig($options);

        $this->assertEquals('$6$rounds=8000$CCCCCCC.', $config);
        $this->assertSame($options, SHA512Crypt::parseConfig($config));
    }

}
