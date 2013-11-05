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

use Rolebi\ComposerDependenciesSecurityChecker\ScriptHandler;
use SensioLabs\Security\SecurityChecker;

/**
 * @author Ronan Le Bris <ronan.lebris.rolebi@gmail.com>
 */
class ScriptHandlerMocked extends ScriptHandler
{
    /**
     * @var SecurityChecker
     */
    protected static $securityChecker;

    /**
     * @var string
     */
    protected static $composerFile;

    /**
     * {@inheritDoc}
     */
    protected static function getSecurityChecker()
    {
        if (!static::$securityChecker) {
            throw new \RuntimeException(
                'Please set a security checker using ScriptHandlerMocked::setSecurityChecker() before using'
                .'ScriptHandlerMocked::getSecurityChecker()'
            );
        }

        return static::$securityChecker;
    }

    /**
     * {@inheritDoc}
     */
    protected static function getComposerFile()
    {
        if (!static::$composerFile) {
            throw new \RuntimeException(
                'Please set a composerFile using ScriptHandlerMocked::setComposerFile() before using '
                .'ScriptHandlerMocked::getComposerFile()'
            );
        }

        return static::$composerFile;
    }

    /**
     * @param SecurityChecker $securityChecker
     */
    public static function setSecurityChecker(SecurityChecker $securityChecker)
    {
        static::$securityChecker = $securityChecker;
    }

    /**
     * @param string $composerFile
     */
    public static function setComposerFile($composerFile)
    {
        return static::$composerFile = $composerFile;
    }
}
