README
------

What is ComposerDependenciesSecurityChecker ?
---------------------------------------

It is a composer script that use sensio security checker API to check known vulnerabilities in your dependencies.

Installation
------------

Add those lines in your composer.json

```json
"scripts" : {
    "post-update-cmd" : [
        "Smile\\ComposerSecurityCheckerBundle\\ScriptHandler::checkForSecurityIssues"
    ],
    "post-install-cmd" : [
        "Smile\\ComposerSecurityCheckerBundle\\ScriptHandler::checkForSecurityIssues"
    ],
}
```
        
Configuration
-------------

If you do not want to have errors if vulnerabilities are found just add those lines in you composer.json

```json
    "extra" : {
        "rolebi-dependencies-security-checker" : {
            "error-on-vulnerabilities" : false
        }
    }
```

If you want to ignore vulnerabilities for certain package just add

```json
"extra" : {
    "rolebi-dependencies-security-checker" : {
        "ignored-packages" : [ "your/package_name" ]
    }
}
```
