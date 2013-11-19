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

/**
 * @author Ronan Le Bris <ronan.lebris.rolebi@gmail.com>
 */
class ConfigHandler
{
    /**
     * @return string[]
     */
    protected static function getSupportedOptions()
    {
        return array('error-on-vulnerabilities', 'error-on-service-unavailable', 'ignored-packages');
    }

    /**
     * @param array $config
     *
     * @return array
     */
    public static function processConfig(array $config)
    {
        $config = array_merge(
            array(
                'error-on-vulnerabilities'     => true,
                'ignored-packages'             => array(),
                'error-on-service-unavailable' => true
            ),
            $config
        );

        static::validateConfig($config);

        $config['ignored-packages'] = array_flip($config['ignored-packages']);

        return $config;
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
                'The extra.rolebi-dependencies-security-checker settings does not support option(s): '
                .implode(' ', $unknowOptions)
                .'. List of supported option(s): '.implode(', ', $supportedOptions).'.'
            );
        }

        if (!is_array($config['ignored-packages'])) {
            throw new \InvalidArgumentException(
                'The extra.rolebi-dependencies-security-checker.ignored-packages setting must be an array.'
            );
        }

        if (!is_bool($config['error-on-service-unavailable'])) {
            throw new \InvalidArgumentException(
                'The extra.rolebi-dependencies-security-checker.error-on-service-unavailable '
                .'setting must be a boolean value.'
            );
        }

        if (!is_bool($config['error-on-vulnerabilities'])) {
            throw new \InvalidArgumentException(
                'The extra.rolebi-dependencies-security-checker.error-on-vulnerabilities '
                .'setting must be a boolean value.'
            );
        }

    }
}
