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
use Rolebi\ComposerDependenciesSecurityChecker\Exception\UnsafeDependenciesException;
use Rolebi\ComposerDependenciesSecurityChecker\Exception\ServiceUnavailableException;

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
     * @param IOInterface $io
     * @param array       $vulnerabilities
     */
    protected static function dumpVulnerabilities(IOInterface $io, array $vulnerabilities)
    {
        foreach ($vulnerabilities as $package => $infos) {
            $io->write("\n".'  <info>'.$package.'</info> '.$infos['version']);
            foreach ($infos['advisories'] as $key => $advisory) {
                $io->write('    <comment>'.$advisory['title'].'</comment>');
                $io->write('    <info>'.$advisory['link'].'</info>');
                if ($advisory['cve'] && $io->isVeryVerbose()) {
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
        $config = isset($extra['rolebi-dependencies-security-checker'])
            ? $extra['rolebi-dependencies-security-checker'] : array();

        if (!is_array($config)) {
            throw new \InvalidArgumentException(
                'The extra.rolebi-dependencies-security-checker setting must be an array.'
            );
        }

        $config = ConfigHandler::processConfig($config);

        $io = $event->getIO();

        $io->write("\n".'<info>Checking your dependencies for known vulnerabilities using your composer.lock</info>');
        $io->write(
            '<comment>This checker can only detect vulnerabilities that are referenced in the SensioLabs '
            .'security advisories database.</comment>'."\n"
        );

        try {
            $vulnerabilities = static::getVulnerabilities(static::getComposerFile(), $config['ignored-packages']);
        } catch (ServiceUnavailableException $exception) {
            if ($config['error-on-service-unavailable']) {
                throw $exception;
            } else {
                $io->write("\n".'  <error>'.$exception->getMessage().'</error>');

                return;
            }
        }

        $errorCount = count($vulnerabilities);
        if ($errorCount) {
            $io->write("\n".'  <error>'.$errorCount.' vulnerability(ies) found!</error>');

            static::dumpVulnerabilities($io, $vulnerabilities);

            if ($config['error-on-vulnerabilities']) {
                $exception = new UnsafeDependenciesException(
                    'At least one of your dependencies contains known vulnerability(ies)'
                );
                throw $exception->setVulnerabilities($vulnerabilities);
            }
        }
    }

    /**
     * Get vulnerabilities for composer field.
     *
     * @param array $ignoredPackages A list of ignored packages
     *
     * @return array The vulnerabilities map
     */
    protected static function getVulnerabilities($file, array $ignoredPackages = array())
    {
        try {
            $json = static::getSecurityChecker()->check($file, 'json');
        } catch (\RuntimeException $exception) {
            if (false !== strpos('couldn\'t connect to host', $exception->getMessage())) { // Ewww
                throw new ServiceUnavailableException(
                    'SensioLabs security advisories database api is not reachable.',
                    null,
                    $exception
                );
            }

            throw $exception;
        }

        $vulnerabilities = json_decode($json, true); // working with associative array

        return array_diff_key($vulnerabilities, $ignoredPackages);
    }
}
