
# ipm package: UrlNodeJs

## Overview

Partial Implementation of NodeJs&#39; Url library

This is an ipm package, which contains one or more reusable assets within the ipm Community. The 'package.json' in this repo is a ipm spec's package.json, [here](https://docs.clearblade.com/v/3/6-ipm/spec), which is a superset of npm's package.json spec, [here](https://docs.npmjs.com/files/package.json).

[Browse ipm Packages](https://ipm.clearblade.com)


## Setup
Import Just the Code Library, Code Service just gives an exmaple of how to use it.
## Usage
Example Checkout the Code Service, once system is imported.

```javascript
function TestUrlNodeJs(req, resp) {
  var url = UrlNodeJs();
  var parsedUrlObj = url.parse("http://user:pass@host.com:8080/p/a/t/h?query=string#hash");
  // output: {"protocol":"http:","slashes":true,"auth":"user:pass","host":"host.com:8080","port":"8080","hostname":"host.com","hash":"#hash","search":"?query=string","query":"query=string","pathname":"/p/a/t/h","path":"/p/a/t/h?query=string","href":"http://user:pass@host.com:8080/p/a/t/h?query=string#hash"} 
  log(parsedUrlObj);
  resp.success('Success');
}

```
## API
The goal is to provide an API that is identical to [node's Url API](https://nodejs.org/api/url.html). It is modified from [Url](https://github.com/defunctzombie/node-url) library.

## Contributing
PRs are very welcome! The main way to contribute to `UrlNodeJs` is by porting features, bugfixes and tests from Node.js. Ideally, code contributions to this module are copy-pasted from Node.js and transpiled to ES5 (followed by some modifications), rather than reimplemented from scratch. Matching the Node.js code as closely as possible makes maintenance simpler when new changes land in Node.js. This module intends to provide exactly the same API as Node.js, so features that are not available in the core `Url` module will not be accepted. 

If there is a difference in behaviour between Node.js's `Url` module and this module, please open an issue!


