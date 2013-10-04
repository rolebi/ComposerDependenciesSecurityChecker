README
------

What is Dependencies Security Checker for composer ?
---------------------------------------

It is a composer script that use sensio security checker API to check known vulnerabilities in your dependencies.

More informations about Sensio Labs Security Advisories Checker on https://security.sensiolabs.org/


Installation
------------

Add those lines in your composer.json

```json
"require" : {
    "rolebi/composer-dependencies-security-checker": "dev-master"
}
```


```json
"scripts" : {
    "post-update-cmd" : [
        "Rolebi\\ComposerDependenciesSecurityChecker\\ScriptHandler::checkForSecurityIssues"
    ],
    "post-install-cmd" : [
        "Rolebi\\ComposerDependenciesSecurityChecker\\ScriptHandler::checkForSecurityIssues"
    ],
}
```
        
Configuration
-------------

<<<<<<< HEAD
If you don't want to trigger an error when vulnerabilities are found, just add those lines in you composer.json:
=======
If you don't want to trigger an error when vulnerabilities are found, just add those lines in you composer.json
>>>>>>> c2bfa004815fa5f294bdbbcfe40314aa013d7180

```json
"extra" : {
    "rolebi-dependencies-security-checker" : {
        "error-on-vulnerabilities" : false
    }
}
```

<<<<<<< HEAD
If you want to ignore vulnerabilities for certain packages,  just add those lines in you composer.json:
=======
If you want to ignore vulnerabilities for certain package,  just add those lines in you composer.json
>>>>>>> c2bfa004815fa5f294bdbbcfe40314aa013d7180

```json
"extra" : {
    "rolebi-dependencies-security-checker" : {
        "ignored-packages" : [ "your/package_name" ]
    }
}
```
<<<<<<< HEAD

Run Tests
---------

`php composer.phar install --dev; vendor/bin/phpunit`
=======
>>>>>>> c2bfa004815fa5f294bdbbcfe40314aa013d7180
