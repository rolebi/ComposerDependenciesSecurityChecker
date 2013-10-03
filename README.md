README
------

What is Dependencies Security Checker for composer ?
---------------------------------------

It is a composer script that use sensio security checker API to check known vulnerabilities in your dependencies.

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

If you don't want to trigger an error when vulnerabilities are found, just add those lines in you composer.json

```json
"extra" : {
    "rolebi-dependencies-security-checker" : {
        "error-on-vulnerabilities" : false
    }
}
```

If you want to ignore vulnerabilities for certain package,  just add those lines in you composer.json

```json
"extra" : {
    "rolebi-dependencies-security-checker" : {
        "ignored-packages" : [ "your/package_name" ]
    }
}
```
