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

<<<<<<< HEAD
=======
use SensioLabs\Security\SecurityChecker;

>>>>>>> c2bfa004815fa5f294bdbbcfe40314aa013d7180
/**
 * @author Ronan Le Bris <ronan.le-bris@smile.fr>
 */
class UnsafeDependenciesException extends \RuntimeException
{
    /**
<<<<<<< HEAD
     * @var array
=======
     * @var \stdClass
>>>>>>> c2bfa004815fa5f294bdbbcfe40314aa013d7180
     */
    protected $vulnerabilities;

    /**
<<<<<<< HEAD
     * @param array $dependencies As json_decoded result of {@link SensioLabs\Security\SecurityChecker::check()}
     *
     * @return UnsafeDependenciesException
     */
    public function setVulnerabilities(array $vulnerabilities)
=======
     * @param \stdClass $dependencies As json_decoded result of {@link SecurityChecker::check()}
     *
     * @return UnsafeDependenciesException
     */
    public function setVulnerabilities($vulnerabilities)
>>>>>>> c2bfa004815fa5f294bdbbcfe40314aa013d7180
    {
        $this->vulnerabilities = $vulnerabilities;

        return $this;
    }

    /**
<<<<<<< HEAD
     * @return array As json_decoded result of {@link SensioLabs\Security\SecurityChecker::check()}
     */
    public function getVulnerabilities()
    {
        return $this->vulnerabilities;
=======
     * @return \stdClass As json_decoded result of {@link SecurityChecker::check()}
     */
    public function getVulnerabilities()
    {
        return $this->dependencies;
>>>>>>> c2bfa004815fa5f294bdbbcfe40314aa013d7180
    }
}
