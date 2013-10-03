<?php

/*
* This file is part of the rolebi/CompsoserDependenciesSecurityChecker.
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
 * @author Ronan Le Bris <ronan.le-bris@smile.fr>
 */
class ScriptHandler
{
    /**
     * @param Event $event
     */
    public static function checkForSecurityIssues(Event $event)
    {
        $extra  = $event->getComposer()->getPackage()->getExtra();
        $config = static::processConfig(
            isset($extra['rolebi-dependencies-security-checker']) ? $extra['rolebi-dependencies-security-checker'] : array()
        );

        $io = $event->getIO();

        $io->write("\n".'<info>Checking your dependencies for known vulnerabilities using your composer.lock</info>');
        $io->write('<comment>This checker can only detect vulnerabilities that are referenced in the SensioLabs '
            .'security advisories database.</comment>'."\n");

        $checker         = new SecurityChecker();
        $vulnerabilities = json_decode($checker->check(Factory::getComposerFile(), 'json'));

        if ($config['ignored-packages']) {
            $aVulnerabilities = array();
            foreach ($vulnerabilities as $package => $infos) {
                if (!isset($config['ignored-packages'][$package])) {
                    $aVulnerabilities[$package] = $infos;
                }
            }
            $vulnerabilities = $aVulnerabilities;
        }

        $errorCount = count($vulnerabilities);
        if ($errorCount) {
            $io->write("\n".'  <error>'.$errorCount.' vulnerabilit'.($errorCount > 1 ? 'ies' : 'y').' found!</error>');

            static::dumpVulnerabilities($io, $aVulnerabilities);

            if ($config['error-on-vulnerabilities']) {
                $exception = new UnsafeDependenciesException('Your dependencies contains known vulnerabilities.');
                throw $exception->setVulnerabilities($vulnerabilities);
            }
        }
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
     * @param array $config
     */
    protected static function validateConfig(array $config)
    {
        if (!is_array($config['ignored-packages'])) {
            throw new \InvalidArgumentException(
                'The extra.rolebi-dependencies-security-checker.ignored-packages setting must be an array.'
           );
        }
    }

    /**
     * @param IOInterface $io
     * @param array       $vulnerabilities
     */
    protected static function dumpVulnerabilities(IOInterface $io, $vulnerabilities)
    {
        foreach ($vulnerabilities as $package => $infos) {
            $io->write("\n".'  <info>'.$package.'</info> '.$infos->version);
            foreach ($infos->advisories as $key => $advisory) {
                $io->write('    <comment>'.$advisory->title.'</comment>');
                if ($advisory->link) {
                    $io->write('    <info>'.$advisory->link.'</info>');
                }
                if (isset($advisory->cve) && $io->isVeryVerbose()) {
                    $io->write('    '.$advisory->cve);
                }
            }
        }
        $io->write("\n");
    }
}
