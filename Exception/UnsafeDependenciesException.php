<?php

/*
* This file is part of the rolebi/ComposerDependenciesSecurityChecker.
*
* (c) 2013 Ronan Le Bris
*
* For the full copyright and license information, please view the LICENSE
* file that was distributed with this source code.
*/

namespace Rolebi\ComposerDependenciesSecurityChecker\Exception;

/**
 * @author Ronan Le Bris <ronan.lebris.rolebi@gmail.com>
 */
class UnsafeDependenciesException extends \RuntimeException
{
    /**
     * @var array
     */
    protected $vulnerabilities;

    /**
     * @param array $dependencies As json_decoded result of {@link SensioLabs\Security\SecurityChecker::check()}
     *
     * @return UnsafeDependenciesException
     */
    public function setVulnerabilities(array $vulnerabilities)
    {
        $this->vulnerabilities = $vulnerabilities;

        return $this;
    }

    /**
     * @return array As json_decoded result of {@link SensioLabs\Security\SecurityChecker::check()}
     */
    public function getVulnerabilities()
    {
        return $this->vulnerabilities;
    }
}
