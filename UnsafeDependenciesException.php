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

use SensioLabs\Security\SecurityChecker;

/**
 * @author Ronan Le Bris <ronan.le-bris@smile.fr>
 */
class UnsafeDependenciesException extends \RuntimeException
{
    /**
     * @var \stdClass
     */
    protected $vulnerabilities;

    /**
     * @param \stdClass $dependencies As json_decoded array returned by {@link SecurityChecker::check()}
     *
     * @return UnsafeDependenciesException
     */
    public function setVulnerabilities($vulnerabilities)
    {
        $this->vulnerabilities = $vulnerabilities;

        return $this;
    }

    /**
     * @return \stdClass As json_decoded array returned by {@link SecurityChecker::check()}
     *
     * @link
     */
    public function getVulnerabilities()
    {
        return $this->dependencies;
    }
}
