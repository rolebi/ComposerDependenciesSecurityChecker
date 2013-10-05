<?php

/*
* This file is part of the rolebi/ComposerDependenciesSecurityChecker.
*
* (c) 2013 Ronan Le Bris
*
* For the full copyright and license information, please view the LICENSE
* file that was distributed with this source code.
*/

namespace Rolebi\ComposerDependenciesSecurityChecker\Tests;

use Composer\IO\IOInterface;
use Composer\Script\Event;
use Composer\IO\NullIO;
use SensioLabs\Security\SecurityChecker;
use Rolebi\ComposerDependenciesSecurityChecker\UnsafeDependenciesException;

/**
 * @author Ronan Le Bris <ronan.lebris.rolebi@gmail.com>
 */
class ScriptHandlerTest extends \PHPUnit_Framework_TestCase
{
    const OUTPUT_VERBOSE      = 1;
    const OUTPUT_VERY_VERBOSE = 2;

    /**
     * @var string $composerFile
     * @var array  $data
     *
     * @return SecurityChecker
     */
    protected function getCheckerMockForFileAndData($composerFile, array $data = array())
    {
        $checker = $this->getMock('SensioLabs\Security\SecurityChecker');
        $checker
            ->expects($this->any())
            ->method('check')
            ->with($this->equalTo($composerFile), $this->equalTo('json'))
            ->will($this->returnValue(json_encode($data)))
        ;

        return $checker;
    }

    /**
     * @param array       $config
     * @param IOInterface $io
     *
     * @return Event
     */
    protected function getEventMockForConfig(array $config = array(), IOInterface $io = null)
    {
        $package  = $this->getMock('Composer\Package\PackageInterface');
        $package
            ->expects($this->atLeastOnce())
            ->method('getExtra')
            ->will($this->returnValue($config))
        ;

        $composer = $this->getMock('Composer\Composer');
        $composer
            ->expects($this->atLeastOnce())
            ->method('getPackage')
            ->will($this->returnValue($package))
        ;

        $event = $this->getMock('Composer\Script\Event', array(), array(), '', false);
        $event
            ->expects($this->atLeastOnce())
            ->method('getComposer')
            ->will($this->returnValue($composer))
        ;
        $event
            ->expects($this->any())
            ->method('getIO')
            ->will($this->returnValue($io ?: new NullIO()))
        ;

        return $event;
    }

    /**
     * @param string[] $lines
     * @param integer  $verbose
     * @param boolean  $strictComparaison Indicate if text must be strictly compared
     *
     * @return IOInterface
     */
    protected function getIOMockForExpectedText(array $lines, $verbosity = self::OUTPUT_VERBOSE, $strictComparaison = false)
    {
        $io      = $this->getMock('Composer\IO\IOInterface');
        $nbLInes = count($lines);

        $io
            ->expects($this->any())
            ->method('isVerbose')
            ->will($this->returnValue($verbosity >= self::OUTPUT_VERBOSE))
        ;

        $io
            ->expects($this->any())
            ->method('isVeryVerbose')
            ->will($this->returnValue($verbosity >= self::OUTPUT_VERY_VERBOSE))
        ;

        if ($strictComparaison) {
            $comparaisonFactory = function (\PHPUnit_Framework_TestCase $testCase, $expected) {
                return $testCase->callback(function ($v) use ($expected) {
                    return $v === $expected;
                });
            };
        } else {
            $comparaisonFactory = function (\PHPUnit_Framework_TestCase $testCase, $expected) {
                return $testCase->callback(function ($v) use ($expected) {
                    return strpos(strip_tags($v), $expected) !== false;
                });
            };
        }

        foreach ($lines as $index => $line) {
            $io
                ->expects($this->at($index))
                ->method('write')
                ->with($comparaisonFactory($this, $line))
            ;
        }

        return $io;
    }

    /**
     * @param array $dataKeys
     *
     * @return array as json_decoded vulnerabilities returned by {@link SecurityChecker::check()}
     */
    protected function getVulnerabilityData(array $dataKeys = array('cve', 'link'))
    {
        $data = array(
            'version'    => 'test-version',
            'advisories' => array(
                'advisory-key' => array(
                    'title' => 'test-title'
                )
            )
        );

        if (in_array('cve', $dataKeys)) {
            $data['advisories']['advisory-key']['cve']  = 'test-cve';
        }

        if (in_array('link', $dataKeys)) {
            $data['advisories']['advisory-key']['link']  = 'test-link';
        }

        return $data;
    }

    public function testInvalidConfigRoot()
    {
        $this->setExpectedException('InvalidArgumentException', 'The extra.rolebi-dependencies-security-checker setting must be an array.');

        ScriptHandlerMocked::checkForSecurityIssues($this->getEventMockForConfig(array(
            'rolebi-dependencies-security-checker' => false)
        ));
    }

    public function testInvalidIgnoredPackages()
    {
        $this->setExpectedException('InvalidArgumentException', 'The extra.rolebi-dependencies-security-checker.ignored-packages setting must be an array.');

        ScriptHandlerMocked::checkForSecurityIssues($this->getEventMockForConfig(array(
            'rolebi-dependencies-security-checker' => array('ignored-packages' => false)
        )));
    }

    public function testInvalidErrorOnVulnerabilities()
    {
        $this->setExpectedException('InvalidArgumentException', 'The extra.rolebi-dependencies-security-checker.error-on-vulnerabilities setting must be a boolean value.');

        ScriptHandlerMocked::checkForSecurityIssues($this->getEventMockForConfig(array(
            'rolebi-dependencies-security-checker' => array('error-on-vulnerabilities' => array())
        )));
    }

    public function testUnknowOption()
    {
        $this->setExpectedException(
            'InvalidArgumentException',
            'The extra.rolebi-dependencies-security-checker settings does not support option: foo. List of supported options: error-on-vulnerabilities ignored-packages.'
        );

        ScriptHandlerMocked::checkForSecurityIssues($this->getEventMockForConfig(array(
            'rolebi-dependencies-security-checker' => array('foo' => 'bar')
        )));
    }

    public function testUnknowOptions()
    {
        $this->setExpectedException(
            'InvalidArgumentException',
            'The extra.rolebi-dependencies-security-checker settings does not support options: foo cari. List of supported options: error-on-vulnerabilities ignored-packages.'
        );

        ScriptHandlerMocked::checkForSecurityIssues($this->getEventMockForConfig(array(
            'rolebi-dependencies-security-checker' => array('foo' => 'bar', 'cari' => 'smatic')
        )));
    }

    public function testErrorOnVulnerabilitiesOption()
    {
        $composerFile = 'composer_lock';
        ScriptHandlerMocked::setComposerFile($composerFile);
        ScriptHandlerMocked::setSecurityChecker(
            $this->getCheckerMockForFileAndData($composerFile, array('test-package' => $this->getVulnerabilityData()))
        );

        ScriptHandlerMocked::checkForSecurityIssues($this->getEventMockForConfig(array(
            'rolebi-dependencies-security-checker' => array('error-on-vulnerabilities' => false)
        )));

        $this->setExpectedException(
            'Rolebi\ComposerDependenciesSecurityChecker\UnsafeDependenciesException',
            'Your dependencies contains known vulnerabilities.'
        );

        ScriptHandlerMocked::checkForSecurityIssues($this->getEventMockForConfig(array(
            'rolebi-dependencies-security-checker' => array('error-on-vulnerabilities' => true)
        )));
    }

    public function testExceptionReturnedVulnerabilities()
    {
        $vulnerabilities = array('test-package' => $this->getVulnerabilityData());

        $composerFile = 'composer_lock';
        ScriptHandlerMocked::setComposerFile($composerFile);
        ScriptHandlerMocked::setSecurityChecker(
            $this->getCheckerMockForFileAndData($composerFile, $vulnerabilities)
        );

        try {
            ScriptHandlerMocked::checkForSecurityIssues($this->getEventMockForConfig(array(
                'rolebi-dependencies-security-checker' => array('error-on-vulnerabilities' => true)
            )));
        } catch (UnsafeDependenciesException $e) {
            $this->assertEquals($vulnerabilities, $e->getVulnerabilities());

            return;
        }

        $this->fail('Expecting UnsafeDependenciesException Exception.');
    }

    public function testIgnoredPackagesOption()
    {
        $composerFile = 'composer_lock';
        ScriptHandlerMocked::setComposerFile($composerFile);
        ScriptHandlerMocked::setSecurityChecker(
            $this->getCheckerMockForFileAndData($composerFile, array('test-package' => $this->getVulnerabilityData()))
        );

        ScriptHandlerMocked::checkForSecurityIssues($this->getEventMockForConfig(array(
            'rolebi-dependencies-security-checker' => array(
                'error-on-vulnerabilities' => true, 'ignored-packages' => array('test-package')
            )
        )));

        $this->setExpectedException(
            'Rolebi\ComposerDependenciesSecurityChecker\UnsafeDependenciesException',
            'Your dependencies contains known vulnerabilities.'
        );

        ScriptHandlerMocked::checkForSecurityIssues($this->getEventMockForConfig(array(
            'rolebi-dependencies-security-checker' => array(
                'error-on-vulnerabilities' => true, 'ignored-packages' => array()
            )
        )));
    }

    public function testNoVulnerabilitiesOuput()
    {
        $composerFile = 'composer_lock';
        ScriptHandlerMocked::setComposerFile($composerFile);
        ScriptHandlerMocked::setSecurityChecker($this->getCheckerMockForFileAndData($composerFile));

        ScriptHandlerMocked::checkForSecurityIssues(
            $this->getEventMockForConfig(
                array(
                    'rolebi-dependencies-security-checker' => array(
                        'error-on-vulnerabilities' => false
                    )
                ),
                $this->getIOMockForExpectedText(array(
                    'Checking your dependencies for known vulnerabilities using your composer.lock',
                    'This checker can only detect vulnerabilities that are referenced in the SensioLabs '
                    .'security advisories database.'
                ))
            )
        );
    }

    public function testVulnerabilitiesOuput()
    {
        $composerFile = 'composer_lock';
        ScriptHandlerMocked::setComposerFile($composerFile);
        ScriptHandlerMocked::setSecurityChecker(
            $this->getCheckerMockForFileAndData(
                $composerFile, array(
                    'test-package1' => $this->getVulnerabilityData(),
                    'test-package2' => $this->getVulnerabilityData()
                )
            )
        );

        ScriptHandlerMocked::checkForSecurityIssues(
            $this->getEventMockForConfig(
                array(
                    'rolebi-dependencies-security-checker' => array(
                        'error-on-vulnerabilities' => false
                    )
                ),
                $this->getIOMockForExpectedText(array(
                    0 =>  'Checking your dependencies for known vulnerabilities using your composer.lock',
                    1 =>  'This checker can only detect vulnerabilities that are referenced in the SensioLabs '
                        .'security advisories database.',
                    2 =>  '2 vulnerabilities found!',
                    3 =>  '  test-package1 test-version',
                    4 =>  '    test-title',
                    5 =>  '    test-link',
                    7 =>  '  test-package2 test-version',
                    8 =>  '    test-title',
                    9 =>  '    test-link',
                    11 => "\n"
                ))
            )
        );
    }

    public function testVulnerabilitiesOuputVerbose()
    {
        $composerFile = 'composer_lock';
        ScriptHandlerMocked::setComposerFile($composerFile);
        ScriptHandlerMocked::setSecurityChecker(
            $this->getCheckerMockForFileAndData(
                $composerFile, array(
                    'test-package1' => $this->getVulnerabilityData(),
                    'test-package2' => $this->getVulnerabilityData()
                )
            )
        );

        ScriptHandlerMocked::checkForSecurityIssues(
            $this->getEventMockForConfig(
                array(
                    'rolebi-dependencies-security-checker' => array(
                        'error-on-vulnerabilities' => false
                    )
                ),
                $this->getIOMockForExpectedText(array(
                    0 =>  'Checking your dependencies for known vulnerabilities using your composer.lock',
                    1 =>  'This checker can only detect vulnerabilities that are referenced in the SensioLabs '
                        .'security advisories database.',
                    2 =>  '2 vulnerabilities found!',
                    3 =>  '  test-package1 test-version',
                    4 =>  '    test-title',
                    5 =>  '    test-link',
                    7 =>  '    test-cve',
                    8 =>  '  test-package2 test-version',
                    9 =>  '    test-title',
                    10 => '    test-link',
                    12 => '    test-cve',
                    13 => "\n"
                ), self::OUTPUT_VERY_VERBOSE)
            )
        );
    }
}
