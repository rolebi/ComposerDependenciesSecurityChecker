[![Build Status](https://travis-ci.org/rolebi/ComposerDependenciesSecurityChecker.png)](https://travis-ci.org/rolebi/ComposerDependenciesSecurityChecker)

What is Dependencies security checker for composer ?
----------------------------------------------------

A composer script that use Sensio Labs Security advisories checker API to check known vulnerabilities of your
dependencies whenever you update and/or install them using composer.

More informations about Sensio Labs Security advisories checker at https://security.sensiolabs.org/


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

If you don't want to trigger an error when vulnerabilities are found, just add those lines in you composer.json:

```json
"extra" : {
    "rolebi-dependencies-security-checker" : {
        "error-on-vulnerabilities" : false
    }
}
```

If you want to ignore vulnerabilities for certain packages,  just add those lines in you composer.json:

```json
"extra" : {
    "rolebi-dependencies-security-checker" : {
        "ignored-packages" : [ "your/package_name" ]
    }
}
```

Run Tests
---------

`php composer.phar install --dev; vendor/bin/phpunit`
