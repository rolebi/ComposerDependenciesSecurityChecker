<?php

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
     * @param $dependencies As json_decoded array returned by {@link SecurityChecker::check()}
     *
     * @return UnsafeDependenciesException
     */
    public function setVulnerabilities($vulnerabilities)
    {
        $this->vulnerabilities = $vulnerabilities;

        return $this;
    }

    /**
     * @return As json_decoded array returned by {@link SecurityChecker::check()}
     *
     * @link
     */
    public function getVulnerabilities()
    {
        return $this->dependencies;
    }
}
