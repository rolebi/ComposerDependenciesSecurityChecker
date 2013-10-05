<?php

/*
* This file is part of the rolebi/ComposerDependenciesSecurityChecker.
*
* (c) 2013 Ronan Le Bris
*
* For the full copyright and license information, please view the LICENSE
* file that was distributed with this source code.
*/

namespace Rolebi\ComposerDependenciesSecurityChecker;

use Composer\IO\IOInterface;
use Composer\Script\Event;
use Composer\Factory;
use SensioLabs\Security\SecurityChecker;

/**
 * @author Ronan Le Bris <ronan.lebris.rolebi@gmail.com>
 */
class ScriptHandler
{
    /**
     * @return SecurityChecker
     */
    protected static function getSecurityChecker()
    {
        return new SecurityChecker();
    }

    /**
     * @return string The current composer.lock absolute path
     */
    protected static function getComposerFile()
    {
        return Factory::getComposerFile();
    }

    /**
     * @param array $config
     *
     * @return array
     */
    protected static function processConfig(array $config)
    {
        if (!isset($config['error-on-vulnerabilities'])) {
            $config['error-on-vulnerabilities'] = true;
        }

        if (!isset($config['ignored-packages'])) {
            $config['ignored-packages'] = array();
        }

        static::validateConfig($config);

        $config['ignored-packages'] = array_flip($config['ignored-packages']);

        return $config;
    }

    /**
     * @return string[]
     */
    protected static function getSupportedOptions()
    {
        return array('error-on-vulnerabilities', 'ignored-packages');
    }

    /**
     * @param array $config
     */
    protected static function validateConfig(array $config)
    {
        $supportedOptions = static::getSupportedOptions();
        $unknowOptions    = array_keys(array_diff_key($config, array_flip($supportedOptions)));
        if ($unknowOptions) {
            throw new \InvalidArgumentException(
                'The extra.rolebi-dependencies-security-checker settings does not support option'.(count($unknowOptions) > 1 ? 's: ' : ': ')
                .implode(' ', $unknowOptions)
                .'. List of supported option'.(count($supportedOptions) > 1 ? 's: ' : ': ').implode(' ', $supportedOptions).'.'
            );
        }

        if (!is_array($config['ignored-packages'])) {
            throw new \InvalidArgumentException(
                'The extra.rolebi-dependencies-security-checker.ignored-packages setting must be an array.'
            );
        }

        if (!is_bool($config['error-on-vulnerabilities'])) {
            throw new \InvalidArgumentException(
                'The extra.rolebi-dependencies-security-checker.error-on-vulnerabilities setting must be a boolean value.'
            );
        }
    }

    /**
     * @param IOInterface $io
     * @param array       $vulnerabilities
     */
    protected static function dumpVulnerabilities(IOInterface $io, array $vulnerabilities)
    {
        foreach ($vulnerabilities as $package => $infos) {
            $io->write("\n".'  <info>'.$package.'</info> '.$infos['version']);
            foreach ($infos['advisories'] as $key => $advisory) {
                $io->write('    <comment>'.$advisory['title'].'</comment>');
                if (isset($advisory['link'])) {
                    $io->write('    <info>'.$advisory['link'].'</info>');
                }
                if (isset($advisory['cve']) && $io->isVeryVerbose()) {
                    $io->write('    '.$advisory['cve']);
                }
            }
        }
        $io->write("\n");
    }

    /**
     * @param Event $event
     */
    public static function checkForSecurityIssues(Event $event)
    {
        $extra  = $event->getComposer()->getPackage()->getExtra();
        $config = isset($extra['rolebi-dependencies-security-checker']) ? $extra['rolebi-dependencies-security-checker'] : array();

        if (!is_array($config)) {
            throw new \InvalidArgumentException('The extra.rolebi-dependencies-security-checker setting must be an array.');
        }

        $config = static::processConfig($config);

        $io = $event->getIO();

        $io->write("\n".'<info>Checking your dependencies for known vulnerabilities using your composer.lock</info>');
        $io->write('<comment>This checker can only detect vulnerabilities that are referenced in the SensioLabs '
            .'security advisories database.</comment>'."\n");

        $vulnerabilities = json_decode(
            static::getSecurityChecker()->check(static::getComposerFile(), 'json'),
            true // working with associative array
        );
        $vulnerabilities = array_diff_key($vulnerabilities, $config['ignored-packages']);

        $errorCount = count($vulnerabilities);
        if ($errorCount) {
            $io->write("\n".'  <error>'.$errorCount.' vulnerabilit'.($errorCount > 1 ? 'ies' : 'y').' found!</error>');

            static::dumpVulnerabilities($io, $vulnerabilities);

            if ($config['error-on-vulnerabilities']) {
                $exception = new UnsafeDependenciesException('Your dependencies contains known vulnerabilities.');
                throw $exception->setVulnerabilities($vulnerabilities);
            }
        }
    }
}
