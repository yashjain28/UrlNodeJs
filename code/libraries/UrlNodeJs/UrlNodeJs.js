// Copyright Joyent, Inc. and other Node contributors.
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the
// "Software"), to deal in the Software without restriction, including
// without limitation the rights to use, copy, modify, merge, publish,
// distribute, sublicense, and/or sell copies of the Software, and to permit
// persons to whom the Software is furnished to do so, subject to the
// following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
// OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
// MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
// NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
// DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
// OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
// USE OR OTHER DEALINGS IN THE SOFTWARE.

/**
 * This is a partial implementation of NodeJs' url library.
 * It has been modified to fit ClearBlade's requirements
 * Thanks to https://github.com/defunctzombie/node-url for src code
 * Usage: const url = UrlNodeJs();
 */
function UrlNodeJs() {
  var punycode = PunycodeNodeJs();
  var querystring = QuerystringNodeJs();
  var util = {
    isString: function (arg) {
      return typeof arg === "string";
    },
    isObject: function (arg) {
      return typeof arg === "object" && arg !== null;
    },
    isNull: function (arg) {
      return arg === null;
    },
    isNullOrUndefined: function (arg) {
      return arg == null;
    }
  };
  var urlReturnObject = {};

  urlReturnObject.parse = urlParse;
  urlReturnObject.resolve = urlResolve;
  urlReturnObject.resolveObject = urlResolveObject;
  urlReturnObject.format = urlFormat;

  urlReturnObject.Url = Url;

  function Url() {
    this.protocol = null;
    this.slashes = null;
    this.auth = null;
    this.host = null;
    this.port = null;
    this.hostname = null;
    this.hash = null;
    this.search = null;
    this.query = null;
    this.pathname = null;
    this.path = null;
    this.href = null;
    //this.uri = null;
  }

  // Reference: RFC 3986, RFC 1808, RFC 2396

  // define these here so at least they only have to be
  // compiled once on the first module load.
  var protocolPattern = /^([a-z0-9.+-]+:)/i,
    portPattern = /:[0-9]*$/,

    // Special case for a simple path URL
    simplePathPattern = /^(\/\/?(?!\/)[^\?\s]*)(\?[^\s]*)?$/,

    // RFC 2396: characters reserved for delimiting URLs.
    // We actually just auto-escape these.
    delims = ['<', '>', '"', '`', ' ', '\r', '\\\\n', '\t'],

    // RFC 2396: characters not allowed for various reasons.
    unwise = ['{', '}', '|', '\\', '^', '`'].concat(delims),

    // Allowed by RFCs, but cause of XSS attacks.  Always escape these.
    autoEscape = ['\''].concat(unwise),
    // Characters that are never ever allowed in a hostname.
    // Note that any invalid chars are also handled, but these
    // are the ones that are *expected* to be seen, so we fast-path
    // them.
    nonHostChars = ['%', '/', '?', ';', '#'].concat(autoEscape),
    hostEndingChars = ['/', '?', '#'],
    hostnameMaxLen = 255,
    hostnamePartPattern = /^[+a-z0-9A-Z_-]{0,63}$/,
    hostnamePartStart = /^([+a-z0-9A-Z_-]{0,63})(.*)$/,
    // protocols that can allow "unsafe" and "unwise" chars.
    unsafeProtocol = {
      'javascript': true,
      'javascript:': true
    },
    // protocols that never have a hostname.
    hostlessProtocol = {
      'javascript': true,
      'javascript:': true
    },
    // protocols that always contain a // bit.
    slashedProtocol = {
      'http': true,
      'https': true,
      'ftp': true,
      'gopher': true,
      'file': true,
      'http:': true,
      'https:': true,
      'ftp:': true,
      'gopher:': true,
      'file:': true
    };

  function urlParse(url, parseQueryString, slashesDenoteHost) {
    if (url && util.isObject(url) && url instanceof Url) return url;

    var u = new Url;
    u.parse(url, parseQueryString, slashesDenoteHost);
    return u;
  }

  Url.prototype.parse = function (url, parseQueryString, slashesDenoteHost) {
    if (!util.isString(url)) {
      throw new TypeError("Parameter 'url' must be a string, not " + typeof url);
    }

    // Copy chrome, IE, opera backslash-handling behavior.
    // Back slashes before the query string get converted to forward slashes
    // See: https://code.google.com/p/chromium/issues/detail?id=25916
    var queryIndex = url.indexOf('?'),
      splitter =
        (queryIndex !== -1 && queryIndex < url.indexOf('#')) ? '?' : '#',
      uSplit = url.split(splitter),
      slashRegex = /\\/g;
    uSplit[0] = uSplit[0].replace(slashRegex, '/');
    url = uSplit.join(splitter);

    var rest = url;

    // trim before proceeding.
    // This is to support parse stuff like "  http://foo.com  \\\\n"
    rest = rest.trim();

    if (!slashesDenoteHost && url.split('#').length === 1) {
      // Try fast path regexp
      var simplePath = simplePathPattern.exec(rest);
      if (simplePath) {
        this.path = rest;
        this.href = rest;
        this.pathname = simplePath[1];
        if (simplePath[2]) {
          this.search = simplePath[2];
          if (parseQueryString) {
            this.query = querystring.parse(this.search.substr(1));
          } else {
            this.query = this.search.substr(1);
          }
        } else if (parseQueryString) {
          this.search = '';
          this.query = {};
        }
        return this;
      }
    }

    var proto = protocolPattern.exec(rest);
    if (proto) {
      proto = proto[0];
      var lowerProto = proto.toLowerCase();
      this.protocol = lowerProto;
      rest = rest.substr(proto.length);
    }

    // figure out if it's got a host
    // user@server is *always* interpreted as a hostname, and url
    // resolution will treat //foo/bar as host=foo,path=bar because that's
    // how the browser resolves relative URLs.
    if (slashesDenoteHost || proto || rest.match(/^\/\/[^@\/]+@[^@\/]+/)) {
      var slashes = rest.substr(0, 2) === '//';
      if (slashes && !(proto && hostlessProtocol[proto])) {
        rest = rest.substr(2);
        this.slashes = true;
      }
    }

    if (!hostlessProtocol[proto] &&
      (slashes || (proto && !slashedProtocol[proto]))) {

      // there's a hostname.
      // the first instance of /, ?, ;, or # ends the host.
      //
      // If there is an @ in the hostname, then non-host chars *are* allowed
      // to the left of the last @ sign, unless some host-ending character
      // comes *before* the @-sign.
      // URLs are obnoxious.
      //
      // ex:
      // http://a@b@c/ => user:a@b host:c
      // http://a@b?@c => user:a host:c path:/?@c

      // v0.12 TODO(isaacs): This is not quite how Chrome does things.
      // Review our test case against browsers more comprehensively.

      // find the first instance of any hostEndingChars
      var hostEnd = -1;
      for (var i = 0; i < hostEndingChars.length; i++) {
        var hec = rest.indexOf(hostEndingChars[i]);
        if (hec !== -1 && (hostEnd === -1 || hec < hostEnd))
          hostEnd = hec;
      }

      // at this point, either we have an explicit point where the
      // auth portion cannot go past, or the last @ char is the decider.
      var auth, atSign;
      if (hostEnd === -1) {
        // atSign can be anywhere.
        atSign = rest.lastIndexOf('@');
      } else {
        // atSign must be in auth portion.
        // http://a@b/c@d => host:b auth:a path:/c@d
        atSign = rest.lastIndexOf('@', hostEnd);
      }

      // Now we have a portion which is definitely the auth.
      // Pull that off.
      if (atSign !== -1) {
        auth = rest.slice(0, atSign);
        rest = rest.slice(atSign + 1);
        this.auth = decodeURIComponent(auth);
      }

      // the host is the remaining to the left of the first non-host char
      hostEnd = -1;
      for (var i = 0; i < nonHostChars.length; i++) {
        var hec = rest.indexOf(nonHostChars[i]);
        if (hec !== -1 && (hostEnd === -1 || hec < hostEnd))
          hostEnd = hec;
      }
      // if we still have not hit it, then the entire thing is a host.
      if (hostEnd === -1)
        hostEnd = rest.length;

      this.host = rest.slice(0, hostEnd);
      rest = rest.slice(hostEnd);

      // pull out port.
      this.parseHost();

      // we've indicated that there is a hostname,
      // so even if it's empty, it has to be present.
      this.hostname = this.hostname || '';

      // if hostname begins with [ and ends with ]
      // assume that it's an IPv6 address.
      var ipv6Hostname = this.hostname[0] === '[' &&
        this.hostname[this.hostname.length - 1] === ']';

      // validate a little.
      if (!ipv6Hostname) {
        var hostparts = this.hostname.split(/\./);
        for (var i = 0, l = hostparts.length; i < l; i++) {
          var part = hostparts[i];
          if (!part) continue;
          if (!part.match(hostnamePartPattern)) {
            var newpart = '';
            for (var j = 0, k = part.length; j < k; j++) {
              if (part.charCodeAt(j) > 127) {
                // we replace non-ASCII char with a temporary placeholder
                // we need this to make sure size of hostname is not
                // broken by replacing non-ASCII by nothing
                newpart += 'x';
              } else {
                newpart += part[j];
              }
            }
            // we test again with ASCII char only
            if (!newpart.match(hostnamePartPattern)) {
              var validParts = hostparts.slice(0, i);
              var notHost = hostparts.slice(i + 1);
              var bit = part.match(hostnamePartStart);
              if (bit) {
                validParts.push(bit[1]);
                notHost.unshift(bit[2]);
              }
              if (notHost.length) {
                rest = '/' + notHost.join('.') + rest;
              }
              this.hostname = validParts.join('.');
              break;
            }
          }
        }
      }

      if (this.hostname.length > hostnameMaxLen) {
        this.hostname = '';
      } else {
        // hostnames are always lower case.
        this.hostname = this.hostname.toLowerCase();
      }

      if (!ipv6Hostname) {
        // IDNA Support: Returns a punycoded representation of "domain".
        // It only converts parts of the domain name that
        // have non-ASCII characters, i.e. it doesn't matter if
        // you call it with a domain that already is ASCII-only.
        this.hostname = punycode.toASCII(this.hostname);
      }

      var p = this.port ? ':' + this.port : '';
      var h = this.hostname || '';
      this.host = h + p;
      this.href += this.host;

      // strip [ and ] from the hostname
      // the host field still retains them, though
      if (ipv6Hostname) {
        this.hostname = this.hostname.substr(1, this.hostname.length - 2);
        if (rest[0] !== '/') {
          rest = '/' + rest;
        }
      }
    }

    // now rest is set to the post-host stuff.
    // chop off any delim chars.
    if (!unsafeProtocol[lowerProto]) {

      // First, make 100% sure that any "autoEscape" chars get
      // escaped, even if encodeURIComponent doesn't think they
      // need to be.
      for (var i = 0, l = autoEscape.length; i < l; i++) {
        var ae = autoEscape[i];
        if (rest.indexOf(ae) === -1)
          continue;
        var esc = encodeURIComponent(ae);
        if (esc === ae) {
          esc = escape(ae);
        }
        rest = rest.split(ae).join(esc);
      }
    }


    // chop off from the tail first.
    var hash = rest.indexOf('#');
    if (hash !== -1) {
      // got a fragment string.
      this.hash = rest.substr(hash);
      rest = rest.slice(0, hash);
    }
    var qm = rest.indexOf('?');
    if (qm !== -1) {
      this.search = rest.substr(qm);
      this.query = rest.substr(qm + 1);
      if (parseQueryString) {
        this.query = querystring.parse(this.query);
      }
      rest = rest.slice(0, qm);
    } else if (parseQueryString) {
      // no query string, but parseQueryString still requested
      this.search = '';
      this.query = {};
    }
    if (rest) this.pathname = rest;
    if (slashedProtocol[lowerProto] &&
      this.hostname && !this.pathname) {
      this.pathname = '/';
    }

    //to support http.request
    if (this.pathname || this.search) {
      var p = this.pathname || '';
      var s = this.search || '';
      this.path = p + s;
    }

    // finally, reconstruct the href based on what has been validated.
    this.href = this.format();
    return this;
  };

  // format a parsed object into a url string
  function urlFormat(obj) {
    // ensure it's an object, and not a string url.
    // If it's an obj, this is a no-op.
    // this way, you can call url_format() on strings
    // to clean up potentially wonky urls.
    if (util.isString(obj)) obj = urlParse(obj);
    if (!(obj instanceof Url)) return Url.prototype.format.call(obj);
    return obj.format();
  }

  Url.prototype.format = function () {
    var auth = this.auth || '';
    if (auth) {
      auth = encodeURIComponent(auth);
      auth = auth.replace(/%3A/i, ':');
      auth += '@';
    }

    var protocol = this.protocol || '',
      pathname = this.pathname || '',
      hash = this.hash || '',
      host = false,
      query = '';

    if (this.host) {
      host = auth + this.host;
    } else if (this.hostname) {
      host = auth + (this.hostname.indexOf(':') === -1 ?
        this.hostname :
        '[' + this.hostname + ']');
      if (this.port) {
        host += ':' + this.port;
      }
    }

    if (this.query &&
      util.isObject(this.query) &&
      Object.keys(this.query).length) {
      query = querystring.stringify(this.query);
    }

    var search = this.search || (query && ('?' + query)) || '';

    if (protocol && protocol.substr(-1) !== ':') protocol += ':';

    // only the slashedProtocols get the //.  Not mailto:, xmpp:, etc.
    // unless they had them to begin with.
    if (this.slashes ||
      (!protocol || slashedProtocol[protocol]) && host !== false) {
      host = '//' + (host || '');
      if (pathname && pathname.charAt(0) !== '/') pathname = '/' + pathname;
    } else if (!host) {
      host = '';
    }

    if (hash && hash.charAt(0) !== '#') hash = '#' + hash;
    if (search && search.charAt(0) !== '?') search = '?' + search;

    pathname = pathname.replace(/[?#]/g, function (match) {
      return encodeURIComponent(match);
    });
    search = search.replace('#', '%23');

    return protocol + host + pathname + search + hash;
  };

  function urlResolve(source, relative) {
    return urlParse(source, false, true).resolve(relative);
  }

  Url.prototype.resolve = function (relative) {
    return this.resolveObject(urlParse(relative, false, true)).format();
  };

  function urlResolveObject(source, relative) {
    if (!source) return relative;
    return urlParse(source, false, true).resolveObject(relative);
  }

  Url.prototype.resolveObject = function (relative) {
    if (util.isString(relative)) {
      var rel = new Url();
      rel.parse(relative, false, true);
      relative = rel;
    }

    var result = new Url();
    var tkeys = Object.keys(this);
    for (var tk = 0; tk < tkeys.length; tk++) {
      var tkey = tkeys[tk];
      result[tkey] = this[tkey];
    }

    // hash is always overridden, no matter what.
    // even href="" will remove it.
    result.hash = relative.hash;

    // if the relative url is empty, then there's nothing left to do here.
    if (relative.href === '') {
      result.href = result.format();
      return result;
    }

    // hrefs like //foo/bar always cut to the protocol.
    if (relative.slashes && !relative.protocol) {
      // take everything except the protocol from relative
      var rkeys = Object.keys(relative);
      for (var rk = 0; rk < rkeys.length; rk++) {
        var rkey = rkeys[rk];
        if (rkey !== 'protocol')
          result[rkey] = relative[rkey];
      }

      //urlParse appends trailing / to urls like http://www.example.com
      if (slashedProtocol[result.protocol] &&
        result.hostname && !result.pathname) {
        result.path = result.pathname = '/';
      }

      result.href = result.format();
      return result;
    }

    if (relative.protocol && relative.protocol !== result.protocol) {
      // if it's a known url protocol, then changing
      // the protocol does weird things
      // first, if it's not file:, then we MUST have a host,
      // and if there was a path
      // to begin with, then we MUST have a path.
      // if it is file:, then the host is dropped,
      // because that's known to be hostless.
      // anything else is assumed to be absolute.
      if (!slashedProtocol[relative.protocol]) {
        var keys = Object.keys(relative);
        for (var v = 0; v < keys.length; v++) {
          var k = keys[v];
          result[k] = relative[k];
        }
        result.href = result.format();
        return result;
      }

      result.protocol = relative.protocol;
      if (!relative.host && !hostlessProtocol[relative.protocol]) {
        var relPath = (relative.pathname || '').split('/');
        while (relPath.length && !(relative.host = relPath.shift()));
        if (!relative.host) relative.host = '';
        if (!relative.hostname) relative.hostname = '';
        if (relPath[0] !== '') relPath.unshift('');
        if (relPath.length < 2) relPath.unshift('');
        result.pathname = relPath.join('/');
      } else {
        result.pathname = relative.pathname;
      }
      result.search = relative.search;
      result.query = relative.query;
      result.host = relative.host || '';
      result.auth = relative.auth;
      result.hostname = relative.hostname || relative.host;
      result.port = relative.port;
      // to support http.request
      if (result.pathname || result.search) {
        var p = result.pathname || '';
        var s = result.search || '';
        result.path = p + s;
      }
      result.slashes = result.slashes || relative.slashes;
      result.href = result.format();
      return result;
    }

    var isSourceAbs = (result.pathname && result.pathname.charAt(0) === '/'),
      isRelAbs = (
        relative.host ||
        relative.pathname && relative.pathname.charAt(0) === '/'
      ),
      mustEndAbs = (isRelAbs || isSourceAbs ||
        (result.host && relative.pathname)),
      removeAllDots = mustEndAbs,
      srcPath = result.pathname && result.pathname.split('/') || [],
      relPath = relative.pathname && relative.pathname.split('/') || [],
      psychotic = result.protocol && !slashedProtocol[result.protocol];

    // if the url is a non-slashed url, then relative
    // links like ../.. should be able
    // to crawl up to the hostname, as well.  This is strange.
    // result.protocol has already been set by now.
    // Later on, put the first path part into the host field.
    if (psychotic) {
      result.hostname = '';
      result.port = null;
      if (result.host) {
        if (srcPath[0] === '') srcPath[0] = result.host;
        else srcPath.unshift(result.host);
      }
      result.host = '';
      if (relative.protocol) {
        relative.hostname = null;
        relative.port = null;
        if (relative.host) {
          if (relPath[0] === '') relPath[0] = relative.host;
          else relPath.unshift(relative.host);
        }
        relative.host = null;
      }
      mustEndAbs = mustEndAbs && (relPath[0] === '' || srcPath[0] === '');
    }

    if (isRelAbs) {
      // it's absolute.
      result.host = (relative.host || relative.host === '') ?
        relative.host : result.host;
      result.hostname = (relative.hostname || relative.hostname === '') ?
        relative.hostname : result.hostname;
      result.search = relative.search;
      result.query = relative.query;
      srcPath = relPath;
      // fall through to the dot-handling below.
    } else if (relPath.length) {
      // it's relative
      // throw away the existing file, and take the new path instead.
      if (!srcPath) srcPath = [];
      srcPath.pop();
      srcPath = srcPath.concat(relPath);
      result.search = relative.search;
      result.query = relative.query;
    } else if (!util.isNullOrUndefined(relative.search)) {
      // just pull out the search.
      // like href='?foo'.
      // Put this after the other two cases because it simplifies the booleans
      if (psychotic) {
        result.hostname = result.host = srcPath.shift();
        //occationaly the auth can get stuck only in host
        //this especially happens in cases like
        //url.resolveObject('mailto:local1@domain1', 'local2@domain2')
        var authInHost = result.host && result.host.indexOf('@') > 0 ?
          result.host.split('@') : false;
        if (authInHost) {
          result.auth = authInHost.shift();
          result.host = result.hostname = authInHost.shift();
        }
      }
      result.search = relative.search;
      result.query = relative.query;
      //to support http.request
      if (!util.isNull(result.pathname) || !util.isNull(result.search)) {
        result.path = (result.pathname ? result.pathname : '') +
          (result.search ? result.search : '');
      }
      result.href = result.format();
      return result;
    }

    if (!srcPath.length) {
      // no path at all.  easy.
      // we've already handled the other stuff above.
      result.pathname = null;
      //to support http.request
      if (result.search) {
        result.path = '/' + result.search;
      } else {
        result.path = null;
      }
      result.href = result.format();
      return result;
    }

    // if a url ENDs in . or .., then it must get a trailing slash.
    // however, if it ends in anything else non-slashy,
    // then it must NOT get a trailing slash.
    var last = srcPath.slice(-1)[0];
    var hasTrailingSlash = (
      (result.host || relative.host || srcPath.length > 1) &&
      (last === '.' || last === '..') || last === '');

    // strip single dots, resolve double dots to parent dir
    // if the path tries to go above the root, `up` ends up > 0
    var up = 0;
    for (var i = srcPath.length; i >= 0; i--) {
      last = srcPath[i];
      if (last === '.') {
        srcPath.splice(i, 1);
      } else if (last === '..') {
        srcPath.splice(i, 1);
        up++;
      } else if (up) {
        srcPath.splice(i, 1);
        up--;
      }
    }

    // if the path is allowed to go above the root, restore leading ..s
    if (!mustEndAbs && !removeAllDots) {
      for (; up--; up) {
        srcPath.unshift('..');
      }
    }

    if (mustEndAbs && srcPath[0] !== '' &&
      (!srcPath[0] || srcPath[0].charAt(0) !== '/')) {
      srcPath.unshift('');
    }

    if (hasTrailingSlash && (srcPath.join('/').substr(-1) !== '/')) {
      srcPath.push('');
    }

    var isAbsolute = srcPath[0] === '' ||
      (srcPath[0] && srcPath[0].charAt(0) === '/');

    // put the host back
    if (psychotic) {
      result.hostname = result.host = isAbsolute ? '' :
        srcPath.length ? srcPath.shift() : '';
      //occationaly the auth can get stuck only in host
      //this especially happens in cases like
      //url.resolveObject('mailto:local1@domain1', 'local2@domain2')
      var authInHost = result.host && result.host.indexOf('@') > 0 ?
        result.host.split('@') : false;
      if (authInHost) {
        result.auth = authInHost.shift();
        result.host = result.hostname = authInHost.shift();
      }
    }

    mustEndAbs = mustEndAbs || (result.host && srcPath.length);

    if (mustEndAbs && !isAbsolute) {
      srcPath.unshift('');
    }

    if (!srcPath.length) {
      result.pathname = null;
      result.path = null;
    } else {
      result.pathname = srcPath.join('/');
    }

    //to support request.http
    if (!util.isNull(result.pathname) || !util.isNull(result.search)) {
      result.path = (result.pathname ? result.pathname : '') +
        (result.search ? result.search : '');
    }
    result.auth = relative.auth || result.auth;
    result.slashes = result.slashes || relative.slashes;
    result.href = result.format();
    return result;
  };

  Url.prototype.parseHost = function () {
    var host = this.host;
    var port = portPattern.exec(host);
    if (port) {
      port = port[0];
      if (port !== ':') {
        this.port = port.substr(1);
      }
      host = host.substr(0, host.length - port.length);
    }
    if (host) this.hostname = host;
  };

  //TODO: Currently Dependencies are resolved here, but will be udpated later.


  /**
   * This is a partial implementation of NodeJs' Punycode library.
   * It has been modified to fit ClearBlade's requirements
   * Thanks to https://github.com/bestiejs/punycode.js for src code
   * Usage: const punycode = PunycodeNodeJs();
   */
  function PunycodeNodeJs() {
    /** Highest positive signed 32-bit float value */
    var maxInt = 2147483647; // aka. 0x7FFFFFFF or 2^31-1

    /** Bootstring parameters */
    var base = 36;
    var tMin = 1;
    var tMax = 26;
    var skew = 38;
    var damp = 700;
    var initialBias = 72;
    var initialN = 128; // 0x80
    var delimiter = '-'; // '\x2D'

    /** Regular expressions */
    var regexPunycode = /^xn--/;
    var regexNonASCII = /[^\0-\x7E]/; // non-ASCII chars
    var regexSeparators = /[\x2E\u3002\uFF0E\uFF61]/g; // RFC 3490 separators

    /** Error messages */
    var errors = {
      'overflow': 'Overflow: input needs wider integers to process',
      'not-basic': 'Illegal input >= 0x80 (not a basic code point)',
      'invalid-input': 'Invalid input'
    };

    /** Convenience shortcuts */
    var baseMinusTMin = base - tMin;
    var floor = Math.floor;
    var stringFromCharCode = String.fromCharCode;

    /*--------------------------------------------------------------------------*/

    /**
    * A generic error utility function.
    * @private
    * @param {String} type The error type.
    * @returns {Error} Throws a `RangeError` with the applicable error message.
    */
    function error(type) {
      throw new RangeError(errors[type]);
    }

    /**
    * A generic `Array#map` utility function.
    * @private
    * @param {Array} array The array to iterate over.
    * @param {Function} callback The function that gets called for every array
    * item.
    * @returns {Array} A new array of values returned by the callback function.
    */
    function map(array, fn) {
      var result = [];
      var length = array.length;
      while (length--) {
        result[length] = fn(array[length]);
      }
      return result;
    }

    /**
    * A simple `Array#map`-like wrapper to work with domain name strings or email
    * addresses.
    * @private
    * @param {String} domain The domain name or email address.
    * @param {Function} callback The function that gets called for every
    * character.
    * @returns {Array} A new string of characters returned by the callback
    * function.
    */
    function mapDomain(string, fn) {
      var parts = string.split('@');
      var result = '';
      if (parts.length > 1) {
        // In email addresses, only the domain name should be punycoded. Leave
        // the local part (i.e. everything up to `@`) intact.
        result = parts[0] + '@';
        string = parts[1];
      }
      // Avoid `split(regex)` for IE8 compatibility. See #17.
      string = string.replace(regexSeparators, '\x2E');
      var labels = string.split('.');
      var encoded = map(labels, fn).join('.');
      return result + encoded;
    }

    /**
    * Creates an array containing the numeric code points of each Unicode
    * character in the string. While JavaScript uses UCS-2 internally,
    * this function will convert a pair of surrogate halves (each of which
    * UCS-2 exposes as separate characters) into a single code point,
    * matching UTF-16.
    * @see `punycode.ucs2.encode`
    * @see <https://mathiasbynens.be/notes/javascript-encoding>
    * @memberOf punycode.ucs2
    * @name decode
    * @param {String} string The Unicode input string (UCS-2).
    * @returns {Array} The new array of code points.
    */
    function ucs2decode(string) {
      var output = [];
      var counter = 0;
      var length = string.length;
      while (counter < length) {
        var value = string.charCodeAt(counter++);
        if (value >= 0xD800 && value <= 0xDBFF && counter < length) {
          // It's a high surrogate, and there is a next character.
          var extra = string.charCodeAt(counter++);
          if ((extra & 0xFC00) == 0xDC00) {
            // Low surrogate.
            output.push(((value & 0x3FF) << 10) + (extra & 0x3FF) + 0x10000);
          } else {
            // It's an unmatched surrogate; only append this code unit, in case the
            // next code unit is the high surrogate of a surrogate pair.
            output.push(value);
            counter--;
          }
        } else {
          output.push(value);
        }
      }
      return output;
    }

    /**
    * Creates a string based on an array of numeric code points.
    * @see `punycode.ucs2.decode`
    * @memberOf punycode.ucs2
    * @name encode
    * @param {Array} codePoints The array of numeric code points.
    * @returns {String} The new Unicode string (UCS-2).
    */
    var ucs2encode = function ucs2encode(array) {
      return String.fromCodePoint.apply(String, array);
    };

    /**
    * Converts a basic code point into a digit/integer.
    * @see `digitToBasic()`
    * @private
    * @param {Number} codePoint The basic numeric code point value.
    * @returns {Number} The numeric value of a basic code point (for use in
    * representing integers) in the range `0` to `base - 1`, or `base` if
    * the code point does not represent a value.
    */
    var basicToDigit = function basicToDigit(codePoint) {
      if (codePoint - 0x30 < 0x0A) {
        return codePoint - 0x16;
      }
      if (codePoint - 0x41 < 0x1A) {
        return codePoint - 0x41;
      }
      if (codePoint - 0x61 < 0x1A) {
        return codePoint - 0x61;
      }
      return base;
    };

    /**
    * Converts a digit/integer into a basic code point.
    * @see `basicToDigit()`
    * @private
    * @param {Number} digit The numeric value of a basic code point.
    * @returns {Number} The basic code point whose value (when used for
    * representing integers) is `digit`, which needs to be in the range
    * `0` to `base - 1`. If `flag` is non-zero, the uppercase form is
    * used; else, the lowercase form is used. The behavior is undefined
    * if `flag` is non-zero and `digit` has no uppercase form.
    */
    var digitToBasic = function digitToBasic(digit, flag) {
      //  0..25 map to ASCII a..z or A..Z
      // 26..35 map to ASCII 0..9
      return digit + 22 + 75 * (digit < 26) - ((flag != 0) << 5);
    };

    /**
    * Bias adaptation function as per section 3.4 of RFC 3492.
    * https://tools.ietf.org/html/rfc3492#section-3.4
    * @private
    */
    var adapt = function adapt(delta, numPoints, firstTime) {
      var k = 0;
      delta = firstTime ? floor(delta / damp) : delta >> 1;
      delta += floor(delta / numPoints);
      for (; /* no initialization */delta > baseMinusTMin * tMax >> 1; k += base) {
        delta = floor(delta / baseMinusTMin);
      }
      return floor(k + (baseMinusTMin + 1) * delta / (delta + skew));
    };

    /**
    * Converts a Punycode string of ASCII-only symbols to a string of Unicode
    * symbols.
    * @memberOf punycode
    * @param {String} input The Punycode string of ASCII-only symbols.
    * @returns {String} The resulting string of Unicode symbols.
    */
    var decode = function decode(input) {
      // Don't use UCS-2.
      var output = [];
      var inputLength = input.length;
      var i = 0;
      var n = initialN;
      var bias = initialBias;

      // Handle the basic code points: let `basic` be the number of input code
      // points before the last delimiter, or `0` if there is none, then copy
      // the first basic code points to the output.

      var basic = input.lastIndexOf(delimiter);
      if (basic < 0) {
        basic = 0;
      }

      for (var j = 0; j < basic; ++j) {
        // if it's not a basic code point
        if (input.charCodeAt(j) >= 0x80) {
          error('not-basic');
        }
        output.push(input.charCodeAt(j));
      }

      // Main decoding loop: start just after the last delimiter if any basic code
      // points were copied; start at the beginning otherwise.

      for (var index = basic > 0 ? basic + 1 : 0; index < inputLength;) /* no final expression */ {

        // `index` is the index of the next character to be consumed.
        // Decode a generalized variable-length integer into `delta`,
        // which gets added to `i`. The overflow checking is easier
        // if we increase `i` as we go, then subtract off its starting
        // value at the end to obtain `delta`.
        var oldi = i;
        for (var w = 1, k = base; ; /* no condition */k += base) {

          if (index >= inputLength) {
            error('invalid-input');
          }

          var digit = basicToDigit(input.charCodeAt(index++));

          if (digit >= base || digit > floor((maxInt - i) / w)) {
            error('overflow');
          }

          i += digit * w;
          var t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;

          if (digit < t) {
            break;
          }

          var baseMinusT = base - t;
          if (w > floor(maxInt / baseMinusT)) {
            error('overflow');
          }

          w *= baseMinusT;
        }

        var out = output.length + 1;
        bias = adapt(i - oldi, out, oldi == 0);

        // `i` was supposed to wrap around from `out` to `0`,
        // incrementing `n` each time, so we'll fix that now:
        if (floor(i / out) > maxInt - n) {
          error('overflow');
        }

        n += floor(i / out);
        i %= out;

        // Insert `n` at position `i` of the output.
        output.splice(i++, 0, n);
      }

      return String.fromCodePoint.apply(String, output);
    };

    /**
    * Converts a string of Unicode symbols (e.g. a domain name label) to a
    * Punycode string of ASCII-only symbols.
    * @memberOf punycode
    * @param {String} input The string of Unicode symbols.
    * @returns {String} The resulting Punycode string of ASCII-only symbols.
    */
    var encode = function encode(input) {
      var output = [];

      // Convert the input in UCS-2 to an array of Unicode code points.
      input = ucs2decode(input);

      // Cache the length.
      var inputLength = input.length;

      // Initialize the state.
      var n = initialN;
      var delta = 0;
      var bias = initialBias;

      // Handle the basic code points.
      for (var _iterator = input, _isArray = Array.isArray(_iterator), _i = 0, _iterator = _isArray ? _iterator : _iterator[Symbol.iterator](); ;) {
        var _ref;

        if (_isArray) {
          if (_i >= _iterator.length) break;
          _ref = _iterator[_i++];
        } else {
          _i = _iterator.next();
          if (_i.done) break;
          _ref = _i.value;
        }

        var currentValue = _ref;

        if (currentValue < 0x80) {
          output.push(stringFromCharCode(currentValue));
        }
      }

      var basicLength = output.length;
      var handledCPCount = basicLength;

      // `handledCPCount` is the number of code points that have been handled;
      // `basicLength` is the number of basic code points.

      // Finish the basic string with a delimiter unless it's empty.
      if (basicLength) {
        output.push(delimiter);
      }

      // Main encoding loop:
      while (handledCPCount < inputLength) {

        // All non-basic code points < n have been handled already. Find the next
        // larger one:
        var m = maxInt;
        for (var _iterator2 = input, _isArray2 = Array.isArray(_iterator2), _i2 = 0, _iterator2 = _isArray2 ? _iterator2 : _iterator2[Symbol.iterator](); ;) {
          var _ref2;

          if (_isArray2) {
            if (_i2 >= _iterator2.length) break;
            _ref2 = _iterator2[_i2++];
          } else {
            _i2 = _iterator2.next();
            if (_i2.done) break;
            _ref2 = _i2.value;
          }

          var _currentValue = _ref2;

          if (_currentValue >= n && _currentValue < m) {
            m = _currentValue;
          }
        }

        // Increase `delta` enough to advance the decoder's <n,i> state to <m,0>,
        // but guard against overflow.
        var handledCPCountPlusOne = handledCPCount + 1;
        if (m - n > floor((maxInt - delta) / handledCPCountPlusOne)) {
          error('overflow');
        }

        delta += (m - n) * handledCPCountPlusOne;
        n = m;

        for (var _iterator3 = input, _isArray3 = Array.isArray(_iterator3), _i3 = 0, _iterator3 = _isArray3 ? _iterator3 : _iterator3[Symbol.iterator](); ;) {
          var _ref3;

          if (_isArray3) {
            if (_i3 >= _iterator3.length) break;
            _ref3 = _iterator3[_i3++];
          } else {
            _i3 = _iterator3.next();
            if (_i3.done) break;
            _ref3 = _i3.value;
          }

          var _currentValue2 = _ref3;

          if (_currentValue2 < n && ++delta > maxInt) {
            error('overflow');
          }
          if (_currentValue2 == n) {
            // Represent delta as a generalized variable-length integer.
            var q = delta;
            for (var k = base; ; /* no condition */k += base) {
              var t = k <= bias ? tMin : k >= bias + tMax ? tMax : k - bias;
              if (q < t) {
                break;
              }
              var qMinusT = q - t;
              var baseMinusT = base - t;
              output.push(stringFromCharCode(digitToBasic(t + qMinusT % baseMinusT, 0)));
              q = floor(qMinusT / baseMinusT);
            }

            output.push(stringFromCharCode(digitToBasic(q, 0)));
            bias = adapt(delta, handledCPCountPlusOne, handledCPCount == basicLength);
            delta = 0;
            ++handledCPCount;
          }
        }

        ++delta;
        ++n;
      }
      return output.join('');
    };

    /**
    * Converts a Punycode string representing a domain name or an email address
    * to Unicode. Only the Punycoded parts of the input will be converted, i.e.
    * it doesn't matter if you call it on a string that has already been
    * converted to Unicode.
    * @memberOf punycode
    * @param {String} input The Punycoded domain name or email address to
    * convert to Unicode.
    * @returns {String} The Unicode representation of the given Punycode
    * string.
    */
    var toUnicode = function toUnicode(input) {
      return mapDomain(input, function (string) {
        return regexPunycode.test(string) ? decode(string.slice(4).toLowerCase()) : string;
      });
    };

    /**
    * Converts a Unicode string representing a domain name or an email address to
    * Punycode. Only the non-ASCII parts of the domain name will be converted,
    * i.e. it doesn't matter if you call it with a domain that's already in
    * ASCII.
    * @memberOf punycode
    * @param {String} input The domain name or email address to convert, as a
    * Unicode string.
    * @returns {String} The Punycode representation of the given domain name or
    * email address.
    */
    var toASCII = function toASCII(input) {
      return mapDomain(input, function (string) {
        return regexNonASCII.test(string) ? 'xn--' + encode(string) : string;
      });
    };

    /*--------------------------------------------------------------------------*/

    /** Define the public API */
    var punycode = {
      /**
     * A string representing the current Punycode.js version number.
     * @memberOf punycode
     * @type String
     */
      'version': '2.1.0',
      /**
     * An object of methods to convert from JavaScript's internal character
     * representation (UCS-2) to Unicode code points, and back.
     * @see <https://mathiasbynens.be/notes/javascript-encoding>
     * @memberOf punycode
     * @type Object
     */
      'ucs2': {
        'decode': ucs2decode,
        'encode': ucs2encode
      },
      'decode': decode,
      'encode': encode,
      'toASCII': toASCII,
      'toUnicode': toUnicode
    };
    return punycode;
  }


  /**
   * This is a partial implementation of NodeJs' querystring library.
   * It has been modified to fit ClearBlade's requirements
   * Thanks to https://github.com/mike-spainhower/querystring for src code
   * Usage: const querystring = QuerystringNodeJs();
   */
  function QuerystringNodeJs() {
    var _bufferNode = BufferNodeJs();
    var Buffer = _bufferNode.Buffer;

    var _typeof = typeof Symbol === "function" && typeof Symbol.iterator === "symbol" ? function (obj) { return typeof obj; } : function (obj) { return obj && typeof Symbol === "function" && obj.constructor === Symbol && obj !== Symbol.prototype ? "symbol" : typeof obj; };


    function errorNode() {
      function ERR_INVALID_URI() {
        return "Error with url.., erorr class not yet implemented..";
      };
      return { ERR_INVALID_URI: ERR_INVALID_URI };
    }

    function internalQS() {
      var hexTable = new Array(256);
      for (var i = 0; i < 256; ++i) {
        hexTable[i] = "%" + ((i < 16 ? "0" : "") + i.toString(16)).toUpperCase();
      } var isHexTable = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]; // 0 - 15 // 16 - 31 // 32 - 47 // 48 - 63 // 64 - 79 // 80 - 95 // 96 - 111 // 112 - 127 // 128 ... // ... 256
      return { hexTable: hexTable, isHexTable: isHexTable };
    }


    var _errorNode = errorNode(),
      ERR_INVALID_URI = _errorNode.ERR_INVALID_URI;

    var _internalQS = internalQS(),
      hexTable = _internalQS.hexTable,
      isHexTable = _internalQS.isHexTable;

    var unhexTable = [-1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 0 - 15
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 16 - 31
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 32 - 47
    +0, +1, +2, +3, +4, +5, +6, +7, +8, +9, -1, -1, -1, -1, -1, -1, // 48 - 63
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 64 - 79
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 80 - 95
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 96 - 111
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 112 - 127
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, // 128 ...
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1 // ... 255
    ];
    // a safe fast alternative to decodeURIComponent
    function unescapeBuffer(s, decodeSpaces) {
      var out = Buffer.allocUnsafe(s.length);
      var index = 0;
      var outIndex = 0;
      var currentChar;
      var nextChar;
      var hexHigh;
      var hexLow;
      var maxLength = s.length - 2;
      // Flag to know if some hex chars have been decoded
      var hasHex = false;
      while (index < s.length) {
        currentChar = s.charCodeAt(index);
        if (currentChar === 43 /* '+' */ && decodeSpaces) {
          out[outIndex++] = 32; // ' '
          index++;
          continue;
        }
        if (currentChar === 37 /* '%' */ && index < maxLength) {
          currentChar = s.charCodeAt(++index);
          hexHigh = unhexTable[currentChar];
          if (!(hexHigh >= 0)) {
            out[outIndex++] = 37; // '%'
          } else {
            nextChar = s.charCodeAt(++index);
            hexLow = unhexTable[nextChar];
            if (!(hexLow >= 0)) {
              out[outIndex++] = 37; // '%'
              out[outIndex++] = currentChar;
              currentChar = nextChar;
            } else {
              hasHex = true;
              currentChar = hexHigh * 16 + hexLow;
            }
          }
        }
        out[outIndex++] = currentChar;
        index++;
      }
      return hasHex ? out.slice(0, outIndex) : out;
    }

    function qsUnescape(s, decodeSpaces) {
      try {
        return decodeURIComponent(s);
      } catch (e) {
        return QueryString.unescapeBuffer(s, decodeSpaces).toString();
      }
    }

    // These characters do not need escaping when generating query strings:
    // ! - . _ ~
    // ' ( ) *
    // digits
    // alpha (uppercase)
    // alpha (lowercase)
    var noEscape = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 0 - 15
      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // 16 - 31
      0, 1, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 1, 1, 0, // 32 - 47
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, // 48 - 63
      0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 64 - 79
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 1, // 80 - 95
      0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, // 96 - 111
      1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 1, 0 // 112 - 127
    ];
    // QueryString.escape() replaces encodeURIComponent()
    // http://www.ecma-international.org/ecma-262/5.1/#sec-15.1.3.4
    function qsEscape(str) {
      if (typeof str !== "string") {
        if ((typeof str === "undefined" ? "undefined" : _typeof(str)) === "object") str = String(str); else str += "";
      }
      var out = "";
      var lastPos = 0;

      for (var i = 0; i < str.length; ++i) {
        var c = str.charCodeAt(i);

        // ASCII
        if (c < 0x80) {
          if (noEscape[c] === 1) continue;
          if (lastPos < i) out += str.slice(lastPos, i);
          lastPos = i + 1;
          out += hexTable[c];
          continue;
        }

        if (lastPos < i) out += str.slice(lastPos, i);

        // Multi-byte characters ...
        if (c < 0x800) {
          lastPos = i + 1;
          out += hexTable[0xc0 | c >> 6] + hexTable[0x80 | c & 0x3f];
          continue;
        }
        if (c < 0xd800 || c >= 0xe000) {
          lastPos = i + 1;
          out += hexTable[0xe0 | c >> 12] + hexTable[0x80 | c >> 6 & 0x3f] + hexTable[0x80 | c & 0x3f];
          continue;
        }
        // Surrogate pair
        ++i;

        if (i >= str.length) throw new ERR_INVALID_URI();

        var c2 = str.charCodeAt(i) & 0x3ff;

        lastPos = i + 1;
        c = 0x10000 + ((c & 0x3ff) << 10 | c2);
        out += hexTable[0xf0 | c >> 18] + hexTable[0x80 | c >> 12 & 0x3f] + hexTable[0x80 | c >> 6 & 0x3f] + hexTable[0x80 | c & 0x3f];
      }
      if (lastPos === 0) return str;
      if (lastPos < str.length) return out + str.slice(lastPos);
      return out;
    }

    function stringifyPrimitive(v) {
      if (typeof v === "string") return v;
      if (typeof v === "number" && isFinite(v)) return "" + v;
      if (typeof v === "boolean") return v ? "true" : "false";
      return "";
    }

    function stringify(obj, sep, eq, options) {
      sep = sep || "&";
      eq = eq || "=";

      var encode = QueryString.escape;
      if (options && typeof options.encodeURIComponent === "function") {
        encode = options.encodeURIComponent;
      }

      if (obj !== null && (typeof obj === "undefined" ? "undefined" : _typeof(obj)) === "object") {
        var keys = Object.keys(obj);
        var len = keys.length;
        var flast = len - 1;
        var fields = "";
        for (var i = 0; i < len; ++i) {
          var k = keys[i];
          var v = obj[k];
          var ks = encode(stringifyPrimitive(k)) + eq;

          if (Array.isArray(v)) {
            var vlen = v.length;
            var vlast = vlen - 1;
            for (var j = 0; j < vlen; ++j) {
              fields += ks + encode(stringifyPrimitive(v[j]));
              if (j < vlast) fields += sep;
            }
            if (vlen && i < flast) fields += sep;
          } else {
            fields += ks + encode(stringifyPrimitive(v));
            if (i < flast) fields += sep;
          }
        }
        return fields;
      }
      return "";
    }

    function charCodes(str) {
      if (str.length === 0) return [];
      if (str.length === 1) return [str.charCodeAt(0)];
      var ret = [];
      for (var i = 0; i < str.length; ++i) {
        ret[ret.length] = str.charCodeAt(i);
      } return ret;
    }
    var defSepCodes = [38]; // &
    var defEqCodes = [61]; // =

    // Parse a key/val string.
    function parse(qs, sep, eq, options) {
      var obj = Object.create(null);

      if (typeof qs !== "string" || qs.length === 0) {
        return obj;
      }

      var sepCodes = !sep ? defSepCodes : charCodes(sep + "");
      var eqCodes = !eq ? defEqCodes : charCodes(eq + "");
      var sepLen = sepCodes.length;
      var eqLen = eqCodes.length;

      var pairs = 1000;
      if (options && typeof options.maxKeys === "number") {
        // -1 is used in place of a value like Infinity for meaning
        // "unlimited pairs" because of additional checks V8 (at least as of v5.4)
        // has to do when using variables that contain values like Infinity. Since
        // `pairs` is always decremented and checked explicitly for 0, -1 works
        // effectively the same as Infinity, while providing a significant
        // performance boost.
        pairs = options.maxKeys > 0 ? options.maxKeys : -1;
      }

      var decode = QueryString.unescape;
      if (options && typeof options.decodeURIComponent === "function") {
        decode = options.decodeURIComponent;
      }
      var customDecode = decode !== qsUnescape;

      var lastPos = 0;
      var sepIdx = 0;
      var eqIdx = 0;
      var key = "";
      var value = "";
      var keyEncoded = customDecode;
      var valEncoded = customDecode;
      var plusChar = customDecode ? "%20" : " ";
      var encodeCheck = 0;
      for (var i = 0; i < qs.length; ++i) {
        var code = qs.charCodeAt(i);

        // Try matching key/value pair separator (e.g. '&')
        if (code === sepCodes[sepIdx]) {
          if (++sepIdx === sepLen) {
            // Key/value pair separator match!
            var end = i - sepIdx + 1;
            if (eqIdx < eqLen) {
              // We didn't find the (entire) key/value separator
              if (lastPos < end) {
                // Treat the substring as part of the key instead of the value
                key += qs.slice(lastPos, end);
              } else if (key.length === 0) {
                // We saw an empty substring between separators
                if (--pairs === 0) return obj;
                lastPos = i + 1;
                sepIdx = eqIdx = 0;
                continue;
              }
            } else if (lastPos < end) {
              value += qs.slice(lastPos, end);
            }

            if (key.length > 0 && keyEncoded) key = decodeStr(key, decode);
            if (value.length > 0 && valEncoded) value = decodeStr(value, decode);

            if (obj[key] === undefined) {
              obj[key] = value;
            } else {
              var curValue = obj[key];
              // A simple Array-specific property check is enough here to
              // distinguish from a string value and is faster and still safe
              // since we are generating all of the values being assigned.
              if (curValue.pop) curValue[curValue.length] = value; else obj[key] = [curValue, value];
            }
            if (--pairs === 0) return obj;
            keyEncoded = valEncoded = customDecode;
            key = value = "";
            encodeCheck = 0;
            lastPos = i + 1;
            sepIdx = eqIdx = 0;
          }
        } else {
          sepIdx = 0;
          // Try matching key/value separator (e.g. '=') if we haven't already
          if (eqIdx < eqLen) {
            if (code === eqCodes[eqIdx]) {
              if (++eqIdx === eqLen) {
                // Key/value separator match!
                var _end = i - eqIdx + 1;
                if (lastPos < _end) key += qs.slice(lastPos, _end);
                encodeCheck = 0;
                lastPos = i + 1;
              }
              continue;
            } else {
              eqIdx = 0;
              if (!keyEncoded) {
                // Try to match an (valid) encoded byte once to minimize unnecessary
                // calls to string decoding functions
                if (code === 37 /* % */) {
                  encodeCheck = 1;
                  continue;
                } else if (encodeCheck > 0) {
                  // eslint-disable-next-line no-extra-boolean-cast
                  if (!!isHexTable[code]) {
                    if (++encodeCheck === 3) keyEncoded = true;
                    continue;
                  } else {
                    encodeCheck = 0;
                  }
                }
              }
            }
            if (code === 43 /* + */) {
              if (lastPos < i) key += qs.slice(lastPos, i);
              key += plusChar;
              lastPos = i + 1;
              continue;
            }
          }
          if (code === 43 /* + */) {
            if (lastPos < i) value += qs.slice(lastPos, i);
            value += plusChar;
            lastPos = i + 1;
          } else if (!valEncoded) {
            // Try to match an (valid) encoded byte (once) to minimize unnecessary
            // calls to string decoding functions
            if (code === 37 /* % */) {
              encodeCheck = 1;
            } else if (encodeCheck > 0) {
              // eslint-disable-next-line no-extra-boolean-cast
              if (!!isHexTable[code]) {
                if (++encodeCheck === 3) valEncoded = true;
              } else {
                encodeCheck = 0;
              }
            }
          }
        }
      }

      // Deal with any leftover key or value data
      if (lastPos < qs.length) {
        if (eqIdx < eqLen) key += qs.slice(lastPos); else if (sepIdx < sepLen) value += qs.slice(lastPos);
      } else if (eqIdx === 0 && key.length === 0) {
        // We ended on an empty substring
        return obj;
      }
      if (key.length > 0 && keyEncoded) key = decodeStr(key, decode);
      if (value.length > 0 && valEncoded) value = decodeStr(value, decode);
      if (obj[key] === undefined) {
        obj[key] = value;
      } else {
        var _curValue = obj[key];
        // A simple Array-specific property check is enough here to
        // distinguish from a string value and is faster and still safe since
        // we are generating all of the values being assigned.
        if (_curValue.pop) _curValue[_curValue.length] = value; else obj[key] = [_curValue, value];
      }

      return obj;
    }

    // v8 does not optimize functions with try-catch blocks, so we isolate them here
    // to minimize the damage (Note: no longer true as of V8 5.4 -- but still will
    // not be inlined).
    function decodeStr(s, decoder) {
      try {
        return decoder(s);
      } catch (e) {
        return QueryString.unescape(s, true);
      }
    }

    // `unescape()` is a JS global, so we need to use a different local name
    // `escape()` is a JS global, so we need to use a different local name
    var QueryString = {
      unescapeBuffer: unescapeBuffer,
      unescape: qsUnescape,

      escape: qsEscape,

      stringify: stringify,
      encode: stringify,

      parse: parse,
      decode: parse
    };
    //TODO: Currently, dependency are resolved here, but should be changed later.
    /*
     * The buffer module from node.js, for ClearBlade.
     * Usage Ex: const Buffer = BufferNodeJs().Buffer;
     */
    function BufferNodeJs() {

      var INSPECT_MAX_BYTES = 50;
      var base64 = (function base64() {
        var lookup = [];
        var revLookup = [];
        var Arr = typeof Uint8Array !== "undefined" ? Uint8Array : Array;

        var code =
          "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        for (var i = 0, len = code.length; i < len; ++i) {
          lookup[i] = code[i];
          revLookup[code.charCodeAt(i)] = i;
        }

        // Support decoding URL-safe base64 strings, as Node.js does.
        // See: https://en.wikipedia.org/wiki/Base64#URL_applications
        revLookup["-".charCodeAt(0)] = 62;
        revLookup["_".charCodeAt(0)] = 63;

        function getLens(b64) {
          var len = b64.length;

          if (len % 4 > 0) {
            throw new Error("Invalid string. Length must be a multiple of 4");
          }

          // Trim off extra bytes after placeholder bytes are found
          // See: https://github.com/beatgammit/base64-js/issues/42
          var validLen = b64.indexOf("=");
          if (validLen === -1) validLen = len;

          var placeHoldersLen = validLen === len ? 0 : 4 - (validLen % 4);

          return [validLen, placeHoldersLen];
        }

        // base64 is 4/3 + up to two characters of the original data
        function byteLength(b64) {
          var lens = getLens(b64);
          var validLen = lens[0];
          var placeHoldersLen = lens[1];
          return ((validLen + placeHoldersLen) * 3) / 4 - placeHoldersLen;
        }

        function _byteLength(b64, validLen, placeHoldersLen) {
          return ((validLen + placeHoldersLen) * 3) / 4 - placeHoldersLen;
        }

        function toByteArray(b64) {
          var tmp;
          var lens = getLens(b64);
          var validLen = lens[0];
          var placeHoldersLen = lens[1];

          var arr = new Arr(_byteLength(b64, validLen, placeHoldersLen));

          var curByte = 0;

          // if there are placeholders, only get up to the last complete 4 chars
          var len = placeHoldersLen > 0 ? validLen - 4 : validLen;

          for (var i = 0; i < len; i += 4) {
            tmp =
              (revLookup[b64.charCodeAt(i)] << 18) |
              (revLookup[b64.charCodeAt(i + 1)] << 12) |
              (revLookup[b64.charCodeAt(i + 2)] << 6) |
              revLookup[b64.charCodeAt(i + 3)];
            arr[curByte++] = (tmp >> 16) & 0xff;
            arr[curByte++] = (tmp >> 8) & 0xff;
            arr[curByte++] = tmp & 0xff;
          }

          if (placeHoldersLen === 2) {
            tmp =
              (revLookup[b64.charCodeAt(i)] << 2) |
              (revLookup[b64.charCodeAt(i + 1)] >> 4);
            arr[curByte++] = tmp & 0xff;
          }

          if (placeHoldersLen === 1) {
            tmp =
              (revLookup[b64.charCodeAt(i)] << 10) |
              (revLookup[b64.charCodeAt(i + 1)] << 4) |
              (revLookup[b64.charCodeAt(i + 2)] >> 2);
            arr[curByte++] = (tmp >> 8) & 0xff;
            arr[curByte++] = tmp & 0xff;
          }

          return arr;
        }

        function tripletToBase64(num) {
          return (
            lookup[(num >> 18) & 0x3f] +
            lookup[(num >> 12) & 0x3f] +
            lookup[(num >> 6) & 0x3f] +
            lookup[num & 0x3f]
          );
        }

        function encodeChunk(uint8, start, end) {
          var tmp;
          var output = [];
          for (var i = start; i < end; i += 3) {
            tmp =
              ((uint8[i] << 16) & 0xff0000) +
              ((uint8[i + 1] << 8) & 0xff00) +
              (uint8[i + 2] & 0xff);
            output.push(tripletToBase64(tmp));
          }
          return output.join("");
        }

        function fromByteArray(uint8) {
          var tmp;
          var len = uint8.length;
          var extraBytes = len % 3; // if we have 1 byte left, pad 2 bytes
          var parts = [];
          var maxChunkLength = 16383; // must be multiple of 3

          // go through the array every three bytes, we'll deal with trailing stuff later
          for (var i = 0, len2 = len - extraBytes; i < len2; i += maxChunkLength) {
            parts.push(
              encodeChunk(
                uint8,
                i,
                i + maxChunkLength > len2 ? len2 : i + maxChunkLength
              )
            );
          }

          // pad the end with zeros, but make sure to not forget the extra bytes
          if (extraBytes === 1) {
            tmp = uint8[len - 1];
            parts.push(lookup[tmp >> 2] + lookup[(tmp << 4) & 0x3f] + "==");
          } else if (extraBytes === 2) {
            tmp = (uint8[len - 2] << 8) + uint8[len - 1];
            parts.push(
              lookup[tmp >> 10] +
              lookup[(tmp >> 4) & 0x3f] +
              lookup[(tmp << 2) & 0x3f] +
              "="
            );
          }

          return parts.join("");
        }
        return {
          byteLength,
          toByteArray,
          fromByteArray
        };
      })();

      var ieee754 = (function ieee754() {
        function read(buffer, offset, isLE, mLen, nBytes) {
          var e, m;
          var eLen = nBytes * 8 - mLen - 1;
          var eMax = (1 << eLen) - 1;
          var eBias = eMax >> 1;
          var nBits = -7;
          var i = isLE ? nBytes - 1 : 0;
          var d = isLE ? -1 : 1;
          var s = buffer[offset + i];

          i += d;

          e = s & ((1 << -nBits) - 1);
          s >>= -nBits;
          nBits += eLen;
          for (; nBits > 0; e = e * 256 + buffer[offset + i], i += d, nBits -= 8) { }

          m = e & ((1 << -nBits) - 1);
          e >>= -nBits;
          nBits += mLen;
          for (; nBits > 0; m = m * 256 + buffer[offset + i], i += d, nBits -= 8) { }

          if (e === 0) {
            e = 1 - eBias;
          } else if (e === eMax) {
            return m ? NaN : (s ? -1 : 1) * Infinity;
          } else {
            m = m + Math.pow(2, mLen);
            e = e - eBias;
          }
          return (s ? -1 : 1) * m * Math.pow(2, e - mLen);
        }

        function write(buffer, value, offset, isLE, mLen, nBytes) {
          var e, m, c;
          var eLen = nBytes * 8 - mLen - 1;
          var eMax = (1 << eLen) - 1;
          var eBias = eMax >> 1;
          var rt = mLen === 23 ? Math.pow(2, -24) - Math.pow(2, -77) : 0;
          var i = isLE ? 0 : nBytes - 1;
          var d = isLE ? 1 : -1;
          var s = value < 0 || (value === 0 && 1 / value < 0) ? 1 : 0;

          value = Math.abs(value);

          if (isNaN(value) || value === Infinity) {
            m = isNaN(value) ? 1 : 0;
            e = eMax;
          } else {
            e = Math.floor(Math.log(value) / Math.LN2);
            if (value * (c = Math.pow(2, -e)) < 1) {
              e--;
              c *= 2;
            }
            if (e + eBias >= 1) {
              value += rt / c;
            } else {
              value += rt * Math.pow(2, 1 - eBias);
            }
            if (value * c >= 2) {
              e++;
              c /= 2;
            }

            if (e + eBias >= eMax) {
              m = 0;
              e = eMax;
            } else if (e + eBias >= 1) {
              m = (value * c - 1) * Math.pow(2, mLen);
              e = e + eBias;
            } else {
              m = value * Math.pow(2, eBias - 1) * Math.pow(2, mLen);
              e = 0;
            }
          }

          for (
            ;
            mLen >= 8;
            buffer[offset + i] = m & 0xff, i += d, m /= 256, mLen -= 8
          ) { }

          e = (e << mLen) | m;
          eLen += mLen;
          for (
            ;
            eLen > 0;
            buffer[offset + i] = e & 0xff, i += d, e /= 256, eLen -= 8
          ) { }

          buffer[offset + i - d] |= s * 128;
        }
        return {
          read,
          write
        };
      })();

      var isArray = function isarray() {
        var toString = {}.toString;
        return (
          Array.isArray ||
          function (arr) {
            return toString.call(arr) == "[object Array]";
          }
        );
      };

      function typedArraySupport() {
        try {
          var arr = new Uint8Array(1);
          arr.__proto__ = {
            __proto__: Uint8Array.prototype,
            foo: function () {
              return 42;
            }
          };
          return (
            arr.foo() === 42 && // typed array instances can be augmented
            typeof arr.subarray === "function" && // chrome 9-10 lack `subarray`
            arr.subarray(1, 1).byteLength === 0
          ); // ie10 has broken `subarray`
        } catch (e) {
          return false;
        }
      }

      function kMaxLength() {
        return Buffer.TYPED_ARRAY_SUPPORT ? 0x7fffffff : 0x3fffffff;
      }

      function createBuffer(that, length) {
        if (kMaxLength() < length) {
          throw new RangeError("Invalid typed array length");
        }
        if (Buffer.TYPED_ARRAY_SUPPORT) {
          // Return an augmented `Uint8Array` instance, for best performance
          that = new Uint8Array(length);
          that.__proto__ = Buffer.prototype;
        } else {
          // Fallback: Return an object instance of the Buffer class
          if (that === null) {
            that = new Buffer(length);
          }
          that.length = length;
        }

        return that;
      }

      /**
       * The Buffer constructor returns instances of `Uint8Array` that have their
       * prototype changed to `Buffer.prototype`. Furthermore, `Buffer` is a subclass of
       * `Uint8Array`, so the returned instances will have all the node `Buffer` methods
       * and the `Uint8Array` methods. Square bracket notation works as expected -- it
       * returns a single octet.
       *
       * The `Uint8Array` prototype remains unmodified.
       */

      function Buffer(arg, encodingOrOffset, length) {
        if (!Buffer.TYPED_ARRAY_SUPPORT && !(this instanceof Buffer)) {
          return new Buffer(arg, encodingOrOffset, length);
        }

        // Common case.
        if (typeof arg === "number") {
          if (typeof encodingOrOffset === "string") {
            throw new Error(
              "If encoding is specified then the first argument must be a string"
            );
          }
          return allocUnsafe(this, arg);
        }
        return from(this, arg, encodingOrOffset, length);
      }

      Buffer.poolSize = 8192; // not used by this implementation

      // TODO: Legacy, not needed anymore. Remove in next major version.
      Buffer._augment = function (arr) {
        arr.__proto__ = Buffer.prototype;
        return arr;
      };

      function from(that, value, encodingOrOffset, length) {
        if (typeof value === "number") {
          throw new TypeError('"value" argument must not be a number');
        }

        if (typeof ArrayBuffer !== "undefined" && value instanceof ArrayBuffer) {
          return fromArrayBuffer(that, value, encodingOrOffset, length);
        }

        if (typeof value === "string") {
          return fromString(that, value, encodingOrOffset);
        }

        return fromObject(that, value);
      }

      /**
       * Functionally equivalent to Buffer(arg, encoding) but throws a TypeError
       * if value is a number.
       * Buffer.from(str[, encoding])
       * Buffer.from(array)
       * Buffer.from(buffer)
       * Buffer.from(arrayBuffer[, byteOffset[, length]])
       **/
      Buffer.from = function (value, encodingOrOffset, length) {
        return from(null, value, encodingOrOffset, length);
      };

      if (Buffer.TYPED_ARRAY_SUPPORT) {
        Buffer.prototype.__proto__ = Uint8Array.prototype;
        Buffer.__proto__ = Uint8Array;
        if (
          typeof Symbol !== "undefined" &&
          Symbol.species &&
          Buffer[Symbol.species] === Buffer
        ) {
          // Fix subarray() in ES2016. See: https://github.com/feross/buffer/pull/97
          Object.defineProperty(Buffer, Symbol.species, {
            value: null,
            configurable: true
          });
        }
      }

      function assertSize(size) {
        if (typeof size !== "number") {
          throw new TypeError('"size" argument must be a number');
        } else if (size < 0) {
          throw new RangeError('"size" argument must not be negative');
        }
      }

      function alloc(that, size, fill, encoding) {
        assertSize(size);
        if (size <= 0) {
          return createBuffer(that, size);
        }
        if (fill !== undefined) {
          // Only pay attention to encoding if it's a string. This
          // prevents accidentally sending in a number that would
          // be interpretted as a start offset.
          return typeof encoding === "string"
            ? createBuffer(that, size).fill(fill, encoding)
            : createBuffer(that, size).fill(fill);
        }
        return createBuffer(that, size);
      }

      /**
       * Creates a new filled Buffer instance.
       * alloc(size[, fill[, encoding]])
       **/
      Buffer.alloc = function (size, fill, encoding) {
        return alloc(null, size, fill, encoding);
      };

      function allocUnsafe(that, size) {
        assertSize(size);
        that = createBuffer(that, size < 0 ? 0 : checked(size) | 0);
        if (!Buffer.TYPED_ARRAY_SUPPORT) {
          for (var i = 0; i < size; ++i) {
            that[i] = 0;
          }
        }
        return that;
      }

      /**
       * Equivalent to Buffer(num), by default creates a non-zero-filled Buffer instance.
       * */
      Buffer.allocUnsafe = function (size) {
        return allocUnsafe(null, size);
      };
      /**
       * Equivalent to SlowBuffer(num), by default creates a non-zero-filled Buffer instance.
       */
      Buffer.allocUnsafeSlow = function (size) {
        return allocUnsafe(null, size);
      };

      function fromString(that, string, encoding) {
        if (typeof encoding !== "string" || encoding === "") {
          encoding = "utf8";
        }

        if (!Buffer.isEncoding(encoding)) {
          throw new TypeError('"encoding" must be a valid string encoding');
        }

        var length = byteLength(string, encoding) | 0;
        that = createBuffer(that, length);

        var actual = that.write(string, encoding);

        if (actual !== length) {
          // Writing a hex string, for example, that contains invalid characters will
          // cause everything after the first invalid character to be ignored. (e.g.
          // 'abxxcd' will be treated as 'ab')
          that = that.slice(0, actual);
        }

        return that;
      }

      function fromArrayLike(that, array) {
        var length = array.length < 0 ? 0 : checked(array.length) | 0;
        that = createBuffer(that, length);
        for (var i = 0; i < length; i += 1) {
          that[i] = array[i] & 255;
        }
        return that;
      }

      function fromArrayBuffer(that, array, byteOffset, length) {
        array.byteLength; // this throws if `array` is not a valid ArrayBuffer

        if (byteOffset < 0 || array.byteLength < byteOffset) {
          throw new RangeError("'offset' is out of bounds");
        }

        if (array.byteLength < byteOffset + (length || 0)) {
          throw new RangeError("'length' is out of bounds");
        }

        if (byteOffset === undefined && length === undefined) {
          array = new Uint8Array(array);
        } else if (length === undefined) {
          array = new Uint8Array(array, byteOffset);
        } else {
          array = new Uint8Array(array, byteOffset, length);
        }

        if (Buffer.TYPED_ARRAY_SUPPORT) {
          // Return an augmented `Uint8Array` instance, for best performance
          that = array;
          that.__proto__ = Buffer.prototype;
        } else {
          // Fallback: Return an object instance of the Buffer class
          that = fromArrayLike(that, array);
        }
        return that;
      }

      function fromObject(that, obj) {
        if (Buffer.isBuffer(obj)) {
          var len = checked(obj.length) | 0;
          that = createBuffer(that, len);

          if (that.length === 0) {
            return that;
          }

          obj.copy(that, 0, 0, len);
          return that;
        }

        if (obj) {
          if (
            (typeof ArrayBuffer !== "undefined" &&
              obj.buffer instanceof ArrayBuffer) ||
            "length" in obj
          ) {
            if (typeof obj.length !== "number" || isnan(obj.length)) {
              return createBuffer(that, 0);
            }
            return fromArrayLike(that, obj);
          }

          if (obj.type === "Buffer" && isArray(obj.data)) {
            return fromArrayLike(that, obj.data);
          }
        }

        throw new TypeError(
          "First argument must be a string, Buffer, ArrayBuffer, Array, or array-like object."
        );
      }

      function checked(length) {
        // Note: cannot use `length < kMaxLength()` here because that fails when
        // length is NaN (which is otherwise coerced to zero.)
        if (length >= kMaxLength()) {
          throw new RangeError(
            "Attempt to allocate Buffer larger than maximum " +
            "size: 0x" +
            kMaxLength().toString(16) +
            " bytes"
          );
        }
        return length | 0;
      }

      function SlowBuffer(length) {
        if (+length != length) {
          // eslint-disable-line eqeqeq
          length = 0;
        }
        return Buffer.alloc(+length);
      }

      Buffer.isBuffer = function isBuffer(b) {
        return !!(b != null && b._isBuffer);
      };

      Buffer.compare = function compare(a, b) {
        if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
          throw new TypeError("Arguments must be Buffers");
        }

        if (a === b) return 0;

        var x = a.length;
        var y = b.length;

        for (var i = 0, len = Math.min(x, y); i < len; ++i) {
          if (a[i] !== b[i]) {
            x = a[i];
            y = b[i];
            break;
          }
        }

        if (x < y) return -1;
        if (y < x) return 1;
        return 0;
      };

      Buffer.isEncoding = function isEncoding(encoding) {
        switch (String(encoding).toLowerCase()) {
          case "hex":
          case "utf8":
          case "utf-8":
          case "ascii":
          case "latin1":
          case "binary":
          case "base64":
          case "ucs2":
          case "ucs-2":
          case "utf16le":
          case "utf-16le":
            return true;
          default:
            return false;
        }
      };

      Buffer.concat = function concat(list, length) {
        if (!isArray(list)) {
          throw new TypeError('"list" argument must be an Array of Buffers');
        }

        if (list.length === 0) {
          return Buffer.alloc(0);
        }

        var i;
        if (length === undefined) {
          length = 0;
          for (i = 0; i < list.length; ++i) {
            length += list[i].length;
          }
        }

        var buffer = Buffer.allocUnsafe(length);
        var pos = 0;
        for (i = 0; i < list.length; ++i) {
          var buf = list[i];
          if (!Buffer.isBuffer(buf)) {
            throw new TypeError('"list" argument must be an Array of Buffers');
          }
          buf.copy(buffer, pos);
          pos += buf.length;
        }
        return buffer;
      };

      function byteLength(string, encoding) {
        if (Buffer.isBuffer(string)) {
          return string.length;
        }
        if (
          typeof ArrayBuffer !== "undefined" &&
          typeof ArrayBuffer.isView === "function" &&
          (ArrayBuffer.isView(string) || string instanceof ArrayBuffer)
        ) {
          return string.byteLength;
        }
        if (typeof string !== "string") {
          string = "" + string;
        }

        var len = string.length;
        if (len === 0) return 0;

        // Use a for loop to avoid recursion
        var loweredCase = false;
        for (; ;) {
          switch (encoding) {
            case "ascii":
            case "latin1":
            case "binary":
              return len;
            case "utf8":
            case "utf-8":
            case undefined:
              return utf8ToBytes(string).length;
            case "ucs2":
            case "ucs-2":
            case "utf16le":
            case "utf-16le":
              return len * 2;
            case "hex":
              return len >>> 1;
            case "base64":
              return base64ToBytes(string).length;
            default:
              if (loweredCase) return utf8ToBytes(string).length; // assume utf8
              encoding = ("" + encoding).toLowerCase();
              loweredCase = true;
          }
        }
      }
      Buffer.byteLength = byteLength;

      function slowToString(encoding, start, end) {
        var loweredCase = false;

        // No need to verify that "this.length <= MAX_UINT32" since it's a read-only
        // property of a typed array.

        // This behaves neither like String nor Uint8Array in that we set start/end
        // to their upper/lower bounds if the value passed is out of range.
        // undefined is handled specially as per ECMA-262 6th Edition,
        // Section 13.3.3.7 Runtime Semantics: KeyedBindingInitialization.
        if (start === undefined || start < 0) {
          start = 0;
        }
        // Return early if start > this.length. Done here to prevent potential uint32
        // coercion fail below.
        if (start > this.length) {
          return "";
        }

        if (end === undefined || end > this.length) {
          end = this.length;
        }

        if (end <= 0) {
          return "";
        }

        // Force coersion to uint32. This will also coerce falsey/NaN values to 0.
        end >>>= 0;
        start >>>= 0;

        if (end <= start) {
          return "";
        }

        if (!encoding) encoding = "utf8";

        while (true) {
          switch (encoding) {
            case "hex":
              return hexSlice(this, start, end);

            case "utf8":
            case "utf-8":
              return utf8Slice(this, start, end);

            case "ascii":
              return asciiSlice(this, start, end);

            case "latin1":
            case "binary":
              return latin1Slice(this, start, end);

            case "base64":
              return base64Slice(this, start, end);

            case "ucs2":
            case "ucs-2":
            case "utf16le":
            case "utf-16le":
              return utf16leSlice(this, start, end);

            default:
              if (loweredCase) throw new TypeError("Unknown encoding: " + encoding);
              encoding = (encoding + "").toLowerCase();
              loweredCase = true;
          }
        }
      }

      // The property is used by `Buffer.isBuffer` and `is-buffer` (in Safari 5-7) to detect
      // Buffer instances.
      Buffer.prototype._isBuffer = true;

      function swap(b, n, m) {
        var i = b[n];
        b[n] = b[m];
        b[m] = i;
      }

      Buffer.prototype.swap16 = function swap16() {
        var len = this.length;
        if (len % 2 !== 0) {
          throw new RangeError("Buffer size must be a multiple of 16-bits");
        }
        for (var i = 0; i < len; i += 2) {
          swap(this, i, i + 1);
        }
        return this;
      };

      Buffer.prototype.swap32 = function swap32() {
        var len = this.length;
        if (len % 4 !== 0) {
          throw new RangeError("Buffer size must be a multiple of 32-bits");
        }
        for (var i = 0; i < len; i += 4) {
          swap(this, i, i + 3);
          swap(this, i + 1, i + 2);
        }
        return this;
      };

      Buffer.prototype.swap64 = function swap64() {
        var len = this.length;
        if (len % 8 !== 0) {
          throw new RangeError("Buffer size must be a multiple of 64-bits");
        }
        for (var i = 0; i < len; i += 8) {
          swap(this, i, i + 7);
          swap(this, i + 1, i + 6);
          swap(this, i + 2, i + 5);
          swap(this, i + 3, i + 4);
        }
        return this;
      };

      Buffer.prototype.toString = function toString() {
        var length = this.length | 0;
        if (length === 0) return "";
        if (arguments.length === 0) return utf8Slice(this, 0, length);
        return slowToString.apply(this, arguments);
      };

      Buffer.prototype.equals = function equals(b) {
        if (!Buffer.isBuffer(b)) throw new TypeError("Argument must be a Buffer");
        if (this === b) return true;
        return Buffer.compare(this, b) === 0;
      };

      Buffer.prototype.inspect = function inspect() {
        var str = "";
        var max = INSPECT_MAX_BYTES;
        if (this.length > 0) {
          str = this.toString("hex", 0, max)
            .match(/.{2}/g)
            .join(" ");
          if (this.length > max) str += " ... ";
        }
        return "<Buffer " + str + ">";
      };

      Buffer.prototype.compare = function compare(
        target,
        start,
        end,
        thisStart,
        thisEnd
      ) {
        if (!Buffer.isBuffer(target)) {
          throw new TypeError("Argument must be a Buffer");
        }

        if (start === undefined) {
          start = 0;
        }
        if (end === undefined) {
          end = target ? target.length : 0;
        }
        if (thisStart === undefined) {
          thisStart = 0;
        }
        if (thisEnd === undefined) {
          thisEnd = this.length;
        }

        if (
          start < 0 ||
          end > target.length ||
          thisStart < 0 ||
          thisEnd > this.length
        ) {
          throw new RangeError("out of range index");
        }

        if (thisStart >= thisEnd && start >= end) {
          return 0;
        }
        if (thisStart >= thisEnd) {
          return -1;
        }
        if (start >= end) {
          return 1;
        }

        start >>>= 0;
        end >>>= 0;
        thisStart >>>= 0;
        thisEnd >>>= 0;

        if (this === target) return 0;

        var x = thisEnd - thisStart;
        var y = end - start;
        var len = Math.min(x, y);

        var thisCopy = this.slice(thisStart, thisEnd);
        var targetCopy = target.slice(start, end);

        for (var i = 0; i < len; ++i) {
          if (thisCopy[i] !== targetCopy[i]) {
            x = thisCopy[i];
            y = targetCopy[i];
            break;
          }
        }

        if (x < y) return -1;
        if (y < x) return 1;
        return 0;
      };

      // Finds either the first index of `val` in `buffer` at offset >= `byteOffset`,
      // OR the last index of `val` in `buffer` at offset <= `byteOffset`.
      //
      // Arguments:
      // - buffer - a Buffer to search
      // - val - a string, Buffer, or number
      // - byteOffset - an index into `buffer`; will be clamped to an int32
      // - encoding - an optional encoding, relevant is val is a string
      // - dir - true for indexOf, false for lastIndexOf
      function bidirectionalIndexOf(buffer, val, byteOffset, encoding, dir) {
        // Empty buffer means no match
        if (buffer.length === 0) return -1;

        // Normalize byteOffset
        if (typeof byteOffset === "string") {
          encoding = byteOffset;
          byteOffset = 0;
        } else if (byteOffset > 0x7fffffff) {
          byteOffset = 0x7fffffff;
        } else if (byteOffset < -0x80000000) {
          byteOffset = -0x80000000;
        }
        byteOffset = +byteOffset; // Coerce to Number.
        if (isNaN(byteOffset)) {
          // byteOffset: it it's undefined, null, NaN, "foo", etc, search whole buffer
          byteOffset = dir ? 0 : buffer.length - 1;
        }

        // Normalize byteOffset: negative offsets start from the end of the buffer
        if (byteOffset < 0) byteOffset = buffer.length + byteOffset;
        if (byteOffset >= buffer.length) {
          if (dir) return -1;
          else byteOffset = buffer.length - 1;
        } else if (byteOffset < 0) {
          if (dir) byteOffset = 0;
          else return -1;
        }

        // Normalize val
        if (typeof val === "string") {
          val = Buffer.from(val, encoding);
        }

        // Finally, search either indexOf (if dir is true) or lastIndexOf
        if (Buffer.isBuffer(val)) {
          // Special case: looking for empty string/buffer always fails
          if (val.length === 0) {
            return -1;
          }
          return arrayIndexOf(buffer, val, byteOffset, encoding, dir);
        } else if (typeof val === "number") {
          val = val & 0xff; // Search for a byte value [0-255]
          if (
            Buffer.TYPED_ARRAY_SUPPORT &&
            typeof Uint8Array.prototype.indexOf === "function"
          ) {
            if (dir) {
              return Uint8Array.prototype.indexOf.call(buffer, val, byteOffset);
            } else {
              return Uint8Array.prototype.lastIndexOf.call(buffer, val, byteOffset);
            }
          }
          return arrayIndexOf(buffer, [val], byteOffset, encoding, dir);
        }

        throw new TypeError("val must be string, number or Buffer");
      }

      function arrayIndexOf(arr, val, byteOffset, encoding, dir) {
        var indexSize = 1;
        var arrLength = arr.length;
        var valLength = val.length;

        if (encoding !== undefined) {
          encoding = String(encoding).toLowerCase();
          if (
            encoding === "ucs2" ||
            encoding === "ucs-2" ||
            encoding === "utf16le" ||
            encoding === "utf-16le"
          ) {
            if (arr.length < 2 || val.length < 2) {
              return -1;
            }
            indexSize = 2;
            arrLength /= 2;
            valLength /= 2;
            byteOffset /= 2;
          }
        }

        function read(buf, i) {
          if (indexSize === 1) {
            return buf[i];
          } else {
            return buf.readUInt16BE(i * indexSize);
          }
        }

        var i;
        if (dir) {
          var foundIndex = -1;
          for (i = byteOffset; i < arrLength; i++) {
            if (
              read(arr, i) === read(val, foundIndex === -1 ? 0 : i - foundIndex)
            ) {
              if (foundIndex === -1) foundIndex = i;
              if (i - foundIndex + 1 === valLength) return foundIndex * indexSize;
            } else {
              if (foundIndex !== -1) i -= i - foundIndex;
              foundIndex = -1;
            }
          }
        } else {
          if (byteOffset + valLength > arrLength)
            byteOffset = arrLength - valLength;
          for (i = byteOffset; i >= 0; i--) {
            var found = true;
            for (var j = 0; j < valLength; j++) {
              if (read(arr, i + j) !== read(val, j)) {
                found = false;
                break;
              }
            }
            if (found) return i;
          }
        }

        return -1;
      }

      Buffer.prototype.includes = function includes(val, byteOffset, encoding) {
        return this.indexOf(val, byteOffset, encoding) !== -1;
      };

      Buffer.prototype.indexOf = function indexOf(val, byteOffset, encoding) {
        return bidirectionalIndexOf(this, val, byteOffset, encoding, true);
      };

      Buffer.prototype.lastIndexOf = function lastIndexOf(
        val,
        byteOffset,
        encoding
      ) {
        return bidirectionalIndexOf(this, val, byteOffset, encoding, false);
      };

      function hexWrite(buf, string, offset, length) {
        offset = Number(offset) || 0;
        var remaining = buf.length - offset;
        if (!length) {
          length = remaining;
        } else {
          length = Number(length);
          if (length > remaining) {
            length = remaining;
          }
        }

        // must be an even number of digits
        var strLen = string.length;
        if (strLen % 2 !== 0) throw new TypeError("Invalid hex string");

        if (length > strLen / 2) {
          length = strLen / 2;
        }
        for (var i = 0; i < length; ++i) {
          var parsed = parseInt(string.substr(i * 2, 2), 16);
          if (isNaN(parsed)) return i;
          buf[offset + i] = parsed;
        }
        return i;
      }

      function utf8Write(buf, string, offset, length) {
        return blitBuffer(
          utf8ToBytes(string, buf.length - offset),
          buf,
          offset,
          length
        );
      }

      function asciiWrite(buf, string, offset, length) {
        return blitBuffer(asciiToBytes(string), buf, offset, length);
      }

      function latin1Write(buf, string, offset, length) {
        return asciiWrite(buf, string, offset, length);
      }

      function base64Write(buf, string, offset, length) {
        return blitBuffer(base64ToBytes(string), buf, offset, length);
      }

      function ucs2Write(buf, string, offset, length) {
        return blitBuffer(
          utf16leToBytes(string, buf.length - offset),
          buf,
          offset,
          length
        );
      }

      Buffer.prototype.write = function write(string, offset, length, encoding) {
        // Buffer#write(string)
        if (offset === undefined) {
          encoding = "utf8";
          length = this.length;
          offset = 0;
          // Buffer#write(string, encoding)
        } else if (length === undefined && typeof offset === "string") {
          encoding = offset;
          length = this.length;
          offset = 0;
          // Buffer#write(string, offset[, length][, encoding])
        } else if (isFinite(offset)) {
          offset = offset | 0;
          if (isFinite(length)) {
            length = length | 0;
            if (encoding === undefined) encoding = "utf8";
          } else {
            encoding = length;
            length = undefined;
          }
          // legacy write(string, encoding, offset, length) - remove in v0.13
        } else {
          throw new Error(
            "Buffer.write(string, encoding, offset[, length]) is no longer supported"
          );
        }

        var remaining = this.length - offset;
        if (length === undefined || length > remaining) length = remaining;

        if (
          (string.length > 0 && (length < 0 || offset < 0)) ||
          offset > this.length
        ) {
          throw new RangeError("Attempt to write outside buffer bounds");
        }

        if (!encoding) encoding = "utf8";

        var loweredCase = false;
        for (; ;) {
          switch (encoding) {
            case "hex":
              return hexWrite(this, string, offset, length);

            case "utf8":
            case "utf-8":
              return utf8Write(this, string, offset, length);

            case "ascii":
              return asciiWrite(this, string, offset, length);

            case "latin1":
            case "binary":
              return latin1Write(this, string, offset, length);

            case "base64":
              // Warning: maxLength not taken into account in base64Write
              return base64Write(this, string, offset, length);

            case "ucs2":
            case "ucs-2":
            case "utf16le":
            case "utf-16le":
              return ucs2Write(this, string, offset, length);

            default:
              if (loweredCase) throw new TypeError("Unknown encoding: " + encoding);
              encoding = ("" + encoding).toLowerCase();
              loweredCase = true;
          }
        }
      };

      Buffer.prototype.toJSON = function toJSON() {
        return {
          type: "Buffer",
          data: Array.prototype.slice.call(this._arr || this, 0)
        };
      };

      function base64Slice(buf, start, end) {
        if (start === 0 && end === buf.length) {
          return base64.fromByteArray(buf);
        } else {
          return base64.fromByteArray(buf.slice(start, end));
        }
      }

      function utf8Slice(buf, start, end) {
        end = Math.min(buf.length, end);
        var res = [];

        var i = start;
        while (i < end) {
          var firstByte = buf[i];
          var codePoint = null;
          var bytesPerSequence =
            firstByte > 0xef ? 4 : firstByte > 0xdf ? 3 : firstByte > 0xbf ? 2 : 1;

          if (i + bytesPerSequence <= end) {
            var secondByte, thirdByte, fourthByte, tempCodePoint;

            switch (bytesPerSequence) {
              case 1:
                if (firstByte < 0x80) {
                  codePoint = firstByte;
                }
                break;
              case 2:
                secondByte = buf[i + 1];
                if ((secondByte & 0xc0) === 0x80) {
                  tempCodePoint = ((firstByte & 0x1f) << 0x6) | (secondByte & 0x3f);
                  if (tempCodePoint > 0x7f) {
                    codePoint = tempCodePoint;
                  }
                }
                break;
              case 3:
                secondByte = buf[i + 1];
                thirdByte = buf[i + 2];
                if ((secondByte & 0xc0) === 0x80 && (thirdByte & 0xc0) === 0x80) {
                  tempCodePoint =
                    ((firstByte & 0xf) << 0xc) |
                    ((secondByte & 0x3f) << 0x6) |
                    (thirdByte & 0x3f);
                  if (
                    tempCodePoint > 0x7ff &&
                    (tempCodePoint < 0xd800 || tempCodePoint > 0xdfff)
                  ) {
                    codePoint = tempCodePoint;
                  }
                }
                break;
              case 4:
                secondByte = buf[i + 1];
                thirdByte = buf[i + 2];
                fourthByte = buf[i + 3];
                if (
                  (secondByte & 0xc0) === 0x80 &&
                  (thirdByte & 0xc0) === 0x80 &&
                  (fourthByte & 0xc0) === 0x80
                ) {
                  tempCodePoint =
                    ((firstByte & 0xf) << 0x12) |
                    ((secondByte & 0x3f) << 0xc) |
                    ((thirdByte & 0x3f) << 0x6) |
                    (fourthByte & 0x3f);
                  if (tempCodePoint > 0xffff && tempCodePoint < 0x110000) {
                    codePoint = tempCodePoint;
                  }
                }
            }
          }

          if (codePoint === null) {
            // we did not generate a valid codePoint so insert a
            // replacement char (U+FFFD) and advance only 1 byte
            codePoint = 0xfffd;
            bytesPerSequence = 1;
          } else if (codePoint > 0xffff) {
            // encode to utf16 (surrogate pair dance)
            codePoint -= 0x10000;
            res.push(((codePoint >>> 10) & 0x3ff) | 0xd800);
            codePoint = 0xdc00 | (codePoint & 0x3ff);
          }

          res.push(codePoint);
          i += bytesPerSequence;
        }

        return decodeCodePointsArray(res);
      }

      // Based on http://stackoverflow.com/a/22747272/680742, the browser with
      // the lowest limit is Chrome, with 0x10000 args.
      // We go 1 magnitude less, for safety
      var MAX_ARGUMENTS_LENGTH = 0x1000;

      function decodeCodePointsArray(codePoints) {
        var len = codePoints.length;
        if (len <= MAX_ARGUMENTS_LENGTH) {
          return String.fromCharCode.apply(String, codePoints); // avoid extra slice()
        }

        // Decode in chunks to avoid "call stack size exceeded".
        var res = "";
        var i = 0;
        while (i < len) {
          res += String.fromCharCode.apply(
            String,
            codePoints.slice(i, (i += MAX_ARGUMENTS_LENGTH))
          );
        }
        return res;
      }

      function asciiSlice(buf, start, end) {
        var ret = "";
        end = Math.min(buf.length, end);

        for (var i = start; i < end; ++i) {
          ret += String.fromCharCode(buf[i] & 0x7f);
        }
        return ret;
      }

      function latin1Slice(buf, start, end) {
        var ret = "";
        end = Math.min(buf.length, end);

        for (var i = start; i < end; ++i) {
          ret += String.fromCharCode(buf[i]);
        }
        return ret;
      }

      function hexSlice(buf, start, end) {
        var len = buf.length;

        if (!start || start < 0) start = 0;
        if (!end || end < 0 || end > len) end = len;

        var out = "";
        for (var i = start; i < end; ++i) {
          out += toHex(buf[i]);
        }
        return out;
      }

      function utf16leSlice(buf, start, end) {
        var bytes = buf.slice(start, end);
        var res = "";
        for (var i = 0; i < bytes.length; i += 2) {
          res += String.fromCharCode(bytes[i] + bytes[i + 1] * 256);
        }
        return res;
      }

      Buffer.prototype.slice = function slice(start, end) {
        var len = this.length;
        start = ~~start;
        end = end === undefined ? len : ~~end;

        if (start < 0) {
          start += len;
          if (start < 0) start = 0;
        } else if (start > len) {
          start = len;
        }

        if (end < 0) {
          end += len;
          if (end < 0) end = 0;
        } else if (end > len) {
          end = len;
        }

        if (end < start) end = start;

        var newBuf;
        if (Buffer.TYPED_ARRAY_SUPPORT) {
          newBuf = this.subarray(start, end);
          newBuf.__proto__ = Buffer.prototype;
        } else {
          var sliceLen = end - start;
          newBuf = new Buffer(sliceLen, undefined);
          for (var i = 0; i < sliceLen; ++i) {
            newBuf[i] = this[i + start];
          }
        }

        return newBuf;
      };

      /*
     * Need to make sure that buffer isn't trying to write out of bounds.
     */
      function checkOffset(offset, ext, length) {
        if (offset % 1 !== 0 || offset < 0)
          throw new RangeError("offset is not uint");
        if (offset + ext > length)
          throw new RangeError("Trying to access beyond buffer length");
      }

      Buffer.prototype.readUIntLE = function readUIntLE(
        offset,
        byteLength,
        noAssert
      ) {
        offset = offset | 0;
        byteLength = byteLength | 0;
        if (!noAssert) checkOffset(offset, byteLength, this.length);

        var val = this[offset];
        var mul = 1;
        var i = 0;
        while (++i < byteLength && (mul *= 0x100)) {
          val += this[offset + i] * mul;
        }

        return val;
      };

      Buffer.prototype.readUIntBE = function readUIntBE(
        offset,
        byteLength,
        noAssert
      ) {
        offset = offset | 0;
        byteLength = byteLength | 0;
        if (!noAssert) {
          checkOffset(offset, byteLength, this.length);
        }

        var val = this[offset + --byteLength];
        var mul = 1;
        while (byteLength > 0 && (mul *= 0x100)) {
          val += this[offset + --byteLength] * mul;
        }

        return val;
      };

      Buffer.prototype.readUInt8 = function readUInt8(offset, noAssert) {
        if (!noAssert) checkOffset(offset, 1, this.length);
        return this[offset];
      };

      Buffer.prototype.readUInt16LE = function readUInt16LE(offset, noAssert) {
        if (!noAssert) checkOffset(offset, 2, this.length);
        return this[offset] | (this[offset + 1] << 8);
      };

      Buffer.prototype.readUInt16BE = function readUInt16BE(offset, noAssert) {
        if (!noAssert) checkOffset(offset, 2, this.length);
        return (this[offset] << 8) | this[offset + 1];
      };

      Buffer.prototype.readUInt32LE = function readUInt32LE(offset, noAssert) {
        if (!noAssert) checkOffset(offset, 4, this.length);

        return (
          (this[offset] | (this[offset + 1] << 8) | (this[offset + 2] << 16)) +
          this[offset + 3] * 0x1000000
        );
      };

      Buffer.prototype.readUInt32BE = function readUInt32BE(offset, noAssert) {
        if (!noAssert) checkOffset(offset, 4, this.length);

        return (
          this[offset] * 0x1000000 +
          ((this[offset + 1] << 16) | (this[offset + 2] << 8) | this[offset + 3])
        );
      };

      Buffer.prototype.readIntLE = function readIntLE(
        offset,
        byteLength,
        noAssert
      ) {
        offset = offset | 0;
        byteLength = byteLength | 0;
        if (!noAssert) checkOffset(offset, byteLength, this.length);

        var val = this[offset];
        var mul = 1;
        var i = 0;
        while (++i < byteLength && (mul *= 0x100)) {
          val += this[offset + i] * mul;
        }
        mul *= 0x80;

        if (val >= mul) val -= Math.pow(2, 8 * byteLength);

        return val;
      };

      Buffer.prototype.readIntBE = function readIntBE(
        offset,
        byteLength,
        noAssert
      ) {
        offset = offset | 0;
        byteLength = byteLength | 0;
        if (!noAssert) checkOffset(offset, byteLength, this.length);

        var i = byteLength;
        var mul = 1;
        var val = this[offset + --i];
        while (i > 0 && (mul *= 0x100)) {
          val += this[offset + --i] * mul;
        }
        mul *= 0x80;

        if (val >= mul) val -= Math.pow(2, 8 * byteLength);

        return val;
      };

      Buffer.prototype.readInt8 = function readInt8(offset, noAssert) {
        if (!noAssert) checkOffset(offset, 1, this.length);
        if (!(this[offset] & 0x80)) return this[offset];
        return (0xff - this[offset] + 1) * -1;
      };

      Buffer.prototype.readInt16LE = function readInt16LE(offset, noAssert) {
        if (!noAssert) checkOffset(offset, 2, this.length);
        var val = this[offset] | (this[offset + 1] << 8);
        return val & 0x8000 ? val | 0xffff0000 : val;
      };

      Buffer.prototype.readInt16BE = function readInt16BE(offset, noAssert) {
        if (!noAssert) checkOffset(offset, 2, this.length);
        var val = this[offset + 1] | (this[offset] << 8);
        return val & 0x8000 ? val | 0xffff0000 : val;
      };

      Buffer.prototype.readInt32LE = function readInt32LE(offset, noAssert) {
        if (!noAssert) checkOffset(offset, 4, this.length);

        return (
          this[offset] |
          (this[offset + 1] << 8) |
          (this[offset + 2] << 16) |
          (this[offset + 3] << 24)
        );
      };

      Buffer.prototype.readInt32BE = function readInt32BE(offset, noAssert) {
        if (!noAssert) checkOffset(offset, 4, this.length);

        return (
          (this[offset] << 24) |
          (this[offset + 1] << 16) |
          (this[offset + 2] << 8) |
          this[offset + 3]
        );
      };

      Buffer.prototype.readFloatLE = function readFloatLE(offset, noAssert) {
        if (!noAssert) checkOffset(offset, 4, this.length);
        return ieee754.read(this, offset, true, 23, 4);
      };

      Buffer.prototype.readFloatBE = function readFloatBE(offset, noAssert) {
        if (!noAssert) checkOffset(offset, 4, this.length);
        return ieee754.read(this, offset, false, 23, 4);
      };

      Buffer.prototype.readDoubleLE = function readDoubleLE(offset, noAssert) {
        if (!noAssert) checkOffset(offset, 8, this.length);
        return ieee754.read(this, offset, true, 52, 8);
      };

      Buffer.prototype.readDoubleBE = function readDoubleBE(offset, noAssert) {
        if (!noAssert) checkOffset(offset, 8, this.length);
        return ieee754.read(this, offset, false, 52, 8);
      };

      function checkInt(buf, value, offset, ext, max, min) {
        if (!Buffer.isBuffer(buf))
          throw new TypeError('"buffer" argument must be a Buffer instance');
        if (value > max || value < min)
          throw new RangeError('"value" argument is out of bounds');
        if (offset + ext > buf.length) throw new RangeError("Index out of range");
      }

      Buffer.prototype.writeUIntLE = function writeUIntLE(
        value,
        offset,
        byteLength,
        noAssert
      ) {
        value = +value;
        offset = offset | 0;
        byteLength = byteLength | 0;
        if (!noAssert) {
          var maxBytes = Math.pow(2, 8 * byteLength) - 1;
          checkInt(this, value, offset, byteLength, maxBytes, 0);
        }

        var mul = 1;
        var i = 0;
        this[offset] = value & 0xff;
        while (++i < byteLength && (mul *= 0x100)) {
          this[offset + i] = (value / mul) & 0xff;
        }

        return offset + byteLength;
      };

      Buffer.prototype.writeUIntBE = function writeUIntBE(
        value,
        offset,
        byteLength,
        noAssert
      ) {
        value = +value;
        offset = offset | 0;
        byteLength = byteLength | 0;
        if (!noAssert) {
          var maxBytes = Math.pow(2, 8 * byteLength) - 1;
          checkInt(this, value, offset, byteLength, maxBytes, 0);
        }

        var i = byteLength - 1;
        var mul = 1;
        this[offset + i] = value & 0xff;
        while (--i >= 0 && (mul *= 0x100)) {
          this[offset + i] = (value / mul) & 0xff;
        }

        return offset + byteLength;
      };

      Buffer.prototype.writeUInt8 = function writeUInt8(value, offset, noAssert) {
        value = +value;
        offset = offset | 0;
        if (!noAssert) checkInt(this, value, offset, 1, 0xff, 0);
        if (!Buffer.TYPED_ARRAY_SUPPORT) value = Math.floor(value);
        this[offset] = value & 0xff;
        return offset + 1;
      };

      function objectWriteUInt16(buf, value, offset, littleEndian) {
        if (value < 0) value = 0xffff + value + 1;
        for (var i = 0, j = Math.min(buf.length - offset, 2); i < j; ++i) {
          buf[offset + i] =
            (value & (0xff << (8 * (littleEndian ? i : 1 - i)))) >>>
            ((littleEndian ? i : 1 - i) * 8);
        }
      }

      Buffer.prototype.writeUInt16LE = function writeUInt16LE(
        value,
        offset,
        noAssert
      ) {
        value = +value;
        offset = offset | 0;
        if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0);
        if (Buffer.TYPED_ARRAY_SUPPORT) {
          this[offset] = value & 0xff;
          this[offset + 1] = value >>> 8;
        } else {
          objectWriteUInt16(this, value, offset, true);
        }
        return offset + 2;
      };

      Buffer.prototype.writeUInt16BE = function writeUInt16BE(
        value,
        offset,
        noAssert
      ) {
        value = +value;
        offset = offset | 0;
        if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0);
        if (Buffer.TYPED_ARRAY_SUPPORT) {
          this[offset] = value >>> 8;
          this[offset + 1] = value & 0xff;
        } else {
          objectWriteUInt16(this, value, offset, false);
        }
        return offset + 2;
      };

      function objectWriteUInt32(buf, value, offset, littleEndian) {
        if (value < 0) value = 0xffffffff + value + 1;
        for (var i = 0, j = Math.min(buf.length - offset, 4); i < j; ++i) {
          buf[offset + i] = (value >>> ((littleEndian ? i : 3 - i) * 8)) & 0xff;
        }
      }

      Buffer.prototype.writeUInt32LE = function writeUInt32LE(
        value,
        offset,
        noAssert
      ) {
        value = +value;
        offset = offset | 0;
        if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0);
        if (Buffer.TYPED_ARRAY_SUPPORT) {
          this[offset + 3] = value >>> 24;
          this[offset + 2] = value >>> 16;
          this[offset + 1] = value >>> 8;
          this[offset] = value & 0xff;
        } else {
          objectWriteUInt32(this, value, offset, true);
        }
        return offset + 4;
      };

      Buffer.prototype.writeUInt32BE = function writeUInt32BE(
        value,
        offset,
        noAssert
      ) {
        value = +value;
        offset = offset | 0;
        if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0);
        if (Buffer.TYPED_ARRAY_SUPPORT) {
          this[offset] = value >>> 24;
          this[offset + 1] = value >>> 16;
          this[offset + 2] = value >>> 8;
          this[offset + 3] = value & 0xff;
        } else {
          objectWriteUInt32(this, value, offset, false);
        }
        return offset + 4;
      };

      Buffer.prototype.writeIntLE = function writeIntLE(
        value,
        offset,
        byteLength,
        noAssert
      ) {
        value = +value;
        offset = offset | 0;
        if (!noAssert) {
          var limit = Math.pow(2, 8 * byteLength - 1);

          checkInt(this, value, offset, byteLength, limit - 1, -limit);
        }

        var i = 0;
        var mul = 1;
        var sub = 0;
        this[offset] = value & 0xff;
        while (++i < byteLength && (mul *= 0x100)) {
          if (value < 0 && sub === 0 && this[offset + i - 1] !== 0) {
            sub = 1;
          }
          this[offset + i] = (((value / mul) >> 0) - sub) & 0xff;
        }

        return offset + byteLength;
      };

      Buffer.prototype.writeIntBE = function writeIntBE(
        value,
        offset,
        byteLength,
        noAssert
      ) {
        value = +value;
        offset = offset | 0;
        if (!noAssert) {
          var limit = Math.pow(2, 8 * byteLength - 1);

          checkInt(this, value, offset, byteLength, limit - 1, -limit);
        }

        var i = byteLength - 1;
        var mul = 1;
        var sub = 0;
        this[offset + i] = value & 0xff;
        while (--i >= 0 && (mul *= 0x100)) {
          if (value < 0 && sub === 0 && this[offset + i + 1] !== 0) {
            sub = 1;
          }
          this[offset + i] = (((value / mul) >> 0) - sub) & 0xff;
        }

        return offset + byteLength;
      };

      Buffer.prototype.writeInt8 = function writeInt8(value, offset, noAssert) {
        value = +value;
        offset = offset | 0;
        if (!noAssert) checkInt(this, value, offset, 1, 0x7f, -0x80);
        if (!Buffer.TYPED_ARRAY_SUPPORT) value = Math.floor(value);
        if (value < 0) value = 0xff + value + 1;
        this[offset] = value & 0xff;
        return offset + 1;
      };

      Buffer.prototype.writeInt16LE = function writeInt16LE(
        value,
        offset,
        noAssert
      ) {
        value = +value;
        offset = offset | 0;
        if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000);
        if (Buffer.TYPED_ARRAY_SUPPORT) {
          this[offset] = value & 0xff;
          this[offset + 1] = value >>> 8;
        } else {
          objectWriteUInt16(this, value, offset, true);
        }
        return offset + 2;
      };

      Buffer.prototype.writeInt16BE = function writeInt16BE(
        value,
        offset,
        noAssert
      ) {
        value = +value;
        offset = offset | 0;
        if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000);
        if (Buffer.TYPED_ARRAY_SUPPORT) {
          this[offset] = value >>> 8;
          this[offset + 1] = value & 0xff;
        } else {
          objectWriteUInt16(this, value, offset, false);
        }
        return offset + 2;
      };

      Buffer.prototype.writeInt32LE = function writeInt32LE(
        value,
        offset,
        noAssert
      ) {
        value = +value;
        offset = offset | 0;
        if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000);
        if (Buffer.TYPED_ARRAY_SUPPORT) {
          this[offset] = value & 0xff;
          this[offset + 1] = value >>> 8;
          this[offset + 2] = value >>> 16;
          this[offset + 3] = value >>> 24;
        } else {
          objectWriteUInt32(this, value, offset, true);
        }
        return offset + 4;
      };

      Buffer.prototype.writeInt32BE = function writeInt32BE(
        value,
        offset,
        noAssert
      ) {
        value = +value;
        offset = offset | 0;
        if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000);
        if (value < 0) value = 0xffffffff + value + 1;
        if (Buffer.TYPED_ARRAY_SUPPORT) {
          this[offset] = value >>> 24;
          this[offset + 1] = value >>> 16;
          this[offset + 2] = value >>> 8;
          this[offset + 3] = value & 0xff;
        } else {
          objectWriteUInt32(this, value, offset, false);
        }
        return offset + 4;
      };

      function checkIEEE754(buf, value, offset, ext, max, min) {
        if (offset + ext > buf.length) throw new RangeError("Index out of range");
        if (offset < 0) throw new RangeError("Index out of range");
      }

      function writeFloat(buf, value, offset, littleEndian, noAssert) {
        if (!noAssert) {
          checkIEEE754(
            buf,
            value,
            offset,
            4,
            3.4028234663852886e38,
            -3.4028234663852886e38
          );
        }
        ieee754.write(buf, value, offset, littleEndian, 23, 4);
        return offset + 4;
      }

      Buffer.prototype.writeFloatLE = function writeFloatLE(
        value,
        offset,
        noAssert
      ) {
        return writeFloat(this, value, offset, true, noAssert);
      };

      Buffer.prototype.writeFloatBE = function writeFloatBE(
        value,
        offset,
        noAssert
      ) {
        return writeFloat(this, value, offset, false, noAssert);
      };

      function writeDouble(buf, value, offset, littleEndian, noAssert) {
        if (!noAssert) {
          checkIEEE754(
            buf,
            value,
            offset,
            8,
            1.7976931348623157e308,
            -1.7976931348623157e308
          );
        }
        ieee754.write(buf, value, offset, littleEndian, 52, 8);
        return offset + 8;
      }

      Buffer.prototype.writeDoubleLE = function writeDoubleLE(
        value,
        offset,
        noAssert
      ) {
        return writeDouble(this, value, offset, true, noAssert);
      };

      Buffer.prototype.writeDoubleBE = function writeDoubleBE(
        value,
        offset,
        noAssert
      ) {
        return writeDouble(this, value, offset, false, noAssert);
      };

      // copy(targetBuffer, targetStart=0, sourceStart=0, sourceEnd=buffer.length)
      Buffer.prototype.copy = function copy(target, targetStart, start, end) {
        if (!start) start = 0;
        if (!end && end !== 0) end = this.length;
        if (targetStart >= target.length) targetStart = target.length;
        if (!targetStart) targetStart = 0;
        if (end > 0 && end < start) end = start;

        // Copy 0 bytes; we're done
        if (end === start) return 0;
        if (target.length === 0 || this.length === 0) return 0;

        // Fatal error conditions
        if (targetStart < 0) {
          throw new RangeError("targetStart out of bounds");
        }
        if (start < 0 || start >= this.length)
          throw new RangeError("sourceStart out of bounds");
        if (end < 0) throw new RangeError("sourceEnd out of bounds");

        // Are we oob?
        if (end > this.length) end = this.length;
        if (target.length - targetStart < end - start) {
          end = target.length - targetStart + start;
        }

        var len = end - start;
        var i;

        if (this === target && start < targetStart && targetStart < end) {
          // descending copy from end
          for (i = len - 1; i >= 0; --i) {
            target[i + targetStart] = this[i + start];
          }
        } else if (len < 1000 || !Buffer.TYPED_ARRAY_SUPPORT) {
          // ascending copy from start
          for (i = 0; i < len; ++i) {
            target[i + targetStart] = this[i + start];
          }
        } else {
          Uint8Array.prototype.set.call(
            target,
            this.subarray(start, start + len),
            targetStart
          );
        }

        return len;
      };

      // Usage:
      //    buffer.fill(number[, offset[, end]])
      //    buffer.fill(buffer[, offset[, end]])
      //    buffer.fill(string[, offset[, end]][, encoding])
      Buffer.prototype.fill = function fill(val, start, end, encoding) {
        // Handle string cases:
        if (typeof val === "string") {
          if (typeof start === "string") {
            encoding = start;
            start = 0;
            end = this.length;
          } else if (typeof end === "string") {
            encoding = end;
            end = this.length;
          }
          if (val.length === 1) {
            var code = val.charCodeAt(0);
            if (code < 256) {
              val = code;
            }
          }
          if (encoding !== undefined && typeof encoding !== "string") {
            throw new TypeError("encoding must be a string");
          }
          if (typeof encoding === "string" && !Buffer.isEncoding(encoding)) {
            throw new TypeError("Unknown encoding: " + encoding);
          }
        } else if (typeof val === "number") {
          val = val & 255;
        }

        // Invalid ranges are not set to a default, so can range check early.
        if (start < 0 || this.length < start || this.length < end) {
          throw new RangeError("Out of range index");
        }

        if (end <= start) {
          return this;
        }

        start = start >>> 0;
        end = end === undefined ? this.length : end >>> 0;

        if (!val) val = 0;

        var i;
        if (typeof val === "number") {
          for (i = start; i < end; ++i) {
            this[i] = val;
          }
        } else {
          var bytes = Buffer.isBuffer(val)
            ? val
            : utf8ToBytes(new Buffer(val, encoding).toString());
          var len = bytes.length;
          for (i = 0; i < end - start; ++i) {
            this[i + start] = bytes[i % len];
          }
        }

        return this;
      };

      // HELPER FUNCTIONS
      // ================

      var INVALID_BASE64_RE = /[^+\/0-9A-Za-z-_]/g;

      function base64clean(str) {
        // Node strips out invalid characters like \\\\n and \t from the string, base64-js does not
        str = stringtrim(str).replace(INVALID_BASE64_RE, "");
        // Node converts strings with length < 2 to ''
        if (str.length < 2) return "";
        // Node allows for non-padded base64 strings (missing trailing ===), base64-js does not
        while (str.length % 4 !== 0) {
          str = str + "=";
        }
        return str;
      }

      function stringtrim(str) {
        if (str.trim) return str.trim();
        return str.replace(/^\s+|\s+$/g, "");
      }

      function toHex(n) {
        if (n < 16) return "0" + n.toString(16);
        return n.toString(16);
      }

      function utf8ToBytes(string, units) {
        units = units || Infinity;
        var codePoint;
        var length = string.length;
        var leadSurrogate = null;
        var bytes = [];

        for (var i = 0; i < length; ++i) {
          codePoint = string.charCodeAt(i);

          // is surrogate component
          if (codePoint > 0xd7ff && codePoint < 0xe000) {
            // last char was a lead
            if (!leadSurrogate) {
              // no lead yet
              if (codePoint > 0xdbff) {
                // unexpected trail
                if ((units -= 3) > -1) bytes.push(0xef, 0xbf, 0xbd);
                continue;
              } else if (i + 1 === length) {
                // unpaired lead
                if ((units -= 3) > -1) bytes.push(0xef, 0xbf, 0xbd);
                continue;
              }

              // valid lead
              leadSurrogate = codePoint;

              continue;
            }

            // 2 leads in a row
            if (codePoint < 0xdc00) {
              if ((units -= 3) > -1) bytes.push(0xef, 0xbf, 0xbd);
              leadSurrogate = codePoint;
              continue;
            }

            // valid surrogate pair
            codePoint =
              (((leadSurrogate - 0xd800) << 10) | (codePoint - 0xdc00)) + 0x10000;
          } else if (leadSurrogate) {
            // valid bmp char, but last char was a lead
            if ((units -= 3) > -1) bytes.push(0xef, 0xbf, 0xbd);
          }

          leadSurrogate = null;

          // encode utf8
          if (codePoint < 0x80) {
            if ((units -= 1) < 0) break;
            bytes.push(codePoint);
          } else if (codePoint < 0x800) {
            if ((units -= 2) < 0) break;
            bytes.push((codePoint >> 0x6) | 0xc0, (codePoint & 0x3f) | 0x80);
          } else if (codePoint < 0x10000) {
            if ((units -= 3) < 0) break;
            bytes.push(
              (codePoint >> 0xc) | 0xe0,
              ((codePoint >> 0x6) & 0x3f) | 0x80,
              (codePoint & 0x3f) | 0x80
            );
          } else if (codePoint < 0x110000) {
            if ((units -= 4) < 0) break;
            bytes.push(
              (codePoint >> 0x12) | 0xf0,
              ((codePoint >> 0xc) & 0x3f) | 0x80,
              ((codePoint >> 0x6) & 0x3f) | 0x80,
              (codePoint & 0x3f) | 0x80
            );
          } else {
            throw new Error("Invalid code point");
          }
        }

        return bytes;
      }

      function asciiToBytes(str) {
        var byteArray = [];
        for (var i = 0; i < str.length; ++i) {
          // Node's code seems to be doing this and not & 0x7F..
          byteArray.push(str.charCodeAt(i) & 0xff);
        }
        return byteArray;
      }

      function utf16leToBytes(str, units) {
        var c, hi, lo;
        var byteArray = [];
        for (var i = 0; i < str.length; ++i) {
          if ((units -= 2) < 0) break;

          c = str.charCodeAt(i);
          hi = c >> 8;
          lo = c % 256;
          byteArray.push(lo);
          byteArray.push(hi);
        }

        return byteArray;
      }

      function base64ToBytes(str) {
        return base64.toByteArray(base64clean(str));
      }

      function blitBuffer(src, dst, offset, length) {
        for (var i = 0; i < length; ++i) {
          if (i + offset >= dst.length || i >= src.length) break;
          dst[i + offset] = src[i];
        }
        return i;
      }

      function isnan(val) {
        return val !== val; // eslint-disable-line no-self-compare
      }
      return { kMaxLength, Buffer, INSPECT_MAX_BYTES, SlowBuffer };
    }

    /**
     * The code has been modified using
     * https://github.com/feross/buffer
     * Thanks to Feross Aboukhadijeh <feross@feross.org> <http://feross.org>
     * @license  MIT
     */


    return QueryString;
  }


  return urlReturnObject;
}