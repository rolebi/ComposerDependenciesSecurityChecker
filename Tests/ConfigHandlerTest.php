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

use Rolebi\ComposerDependenciesSecurityChecker\ConfigHandler;

/**
 * @author Ronan Le Bris <ronan.lebris.rolebi@gmail.com>
 */
class ConfigHandlerTest extends \PHPUnit_Framework_TestCase
{
    public function testInvalidIgnoredPackages()
    {
        $this->setExpectedException(
            'InvalidArgumentException',
            'The extra.rolebi-dependencies-security-checker.ignored-packages setting must be an array.'
        );

        ConfigHandler::processConfig(array('ignored-packages' => false));
    }

    public function testInvalidErrorOnVulnerabilities()
    {
        $this->setExpectedException(
            'InvalidArgumentException',
            'The extra.rolebi-dependencies-security-checker.error-on-vulnerabilities setting must be a boolean value.'
        );

        ConfigHandler::processConfig(array('error-on-vulnerabilities' => array()));
    }

    public function testInvalidErrorOnServiceUnavailable()
    {
        $this->setExpectedException(
            'InvalidArgumentException',
            'The extra.rolebi-dependencies-security-checker.error-on-service-unavailable setting '
            .'must be a boolean value.'
        );

        ConfigHandler::processConfig(array('error-on-service-unavailable' => array()));
    }

    public function testUnknowOptions()
    {
        $this->setExpectedException(
            'InvalidArgumentException',
            'The extra.rolebi-dependencies-security-checker settings does not support option(s): foo cari. '
            .'List of supported option(s): error-on-vulnerabilities, error-on-service-unavailable, ignored-packages.'
        );

        ConfigHandler::processConfig(array('foo' => 'bar', 'cari' => 'smatic'));
    }
}
