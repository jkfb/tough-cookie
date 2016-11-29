// https://github.com/stagas/node-shim/blob/master/lib/url.js - MIT licenced

import punycode from '../third/punycode.es6';
import { querystring } from './querystring';

// Reference: RFC 3986, RFC 1808, RFC 2396

// define these here so at least they only have to be
// compiled once on the first module load.
const protocolPattern = /^([a-z0-9.+-]+:)/i;
const portPattern = /:[0-9]+$/;

// RFC 2396: characters reserved for delimiting URLs.
const delims = [ '<', '>', '"', '`', ' ', '\r', '\n', '\t' ];

// RFC 2396: characters not allowed for various reasons.
const unwise = [ '{', '}', '|', '\\', '^', '~', '[', ']', '`' ].concat(delims);

// Allowed by RFCs, but cause of XSS attacks.  Always escape these.
const autoEscape = [ '\'' ];

// Characters that are never ever allowed in a hostname.
// Note that any invalid chars are also handled, but these
// are the ones that are *expected* to be seen, so we fast-path
// them.
const nonHostChars = [ '%', '/', '?', ';', '#' ].concat(unwise).concat(autoEscape);
const nonAuthChars = [ '/', '@', '?', '#' ].concat(delims);
const hostnameMaxLen = 255;
const hostnamePartPattern = /^[a-zA-Z0-9][a-z0-9A-Z_-]{0,62}$/;
const hostnamePartStart = /^([a-zA-Z0-9][a-z0-9A-Z_-]{0,62})(.*)$/;

// protocols that can allow "unsafe" and "unwise" chars.
// eslint-disable-next-line
const unsafeProtocol = { 'javascript': true, 'javascript:': true };

// protocols that never have a hostname.
// eslint-disable-next-line
const hostlessProtocol = { 'javascript': true, 'javascript:': true };

// protocols that always contain a // bit.
const slashedProtocol = {
  'http': true, // eslint-disable-line quote-props
  'https': true, // eslint-disable-line quote-props
  'ftp': true, // eslint-disable-line quote-props
  'gopher': true, // eslint-disable-line quote-props
  'file': true, // eslint-disable-line quote-props
  'http:': true, // eslint-disable-line quote-props
  'https:': true, // eslint-disable-line quote-props
  'ftp:': true, // eslint-disable-line quote-props
  'gopher:': true, // eslint-disable-line quote-props
  'file:': true // eslint-disable-line quote-props
};

const arrayIndexOf = (searchArray, subject) => {
  for (let i = 0; i < searchArray.length; i++) {
    if (searchArray[i] == subject) { // eslint-disable-line
      return i;
    }
  }

  return -1;
};

const parseHost = host => {
  const out = {};
  let port = portPattern.exec(host);

  if (port) {
    port = port[0];
    out.port = port.substr(1);
    host = host.substr(0, host.length - port.length);
  }

  if (host) {
    out.hostname = host;
  }

  return out;
};

const parse = (url, parseQueryString, slashesDenoteHost) => {
  if (url && typeof url === 'object' && url.href) {
    return url;
  }

  if (typeof url !== 'string') {
    throw new TypeError(`Parameter 'url' must be a string, not ${typeof url}`);
  }

  const out = {};
  let rest = url;

  // cut off any delimiters.
  // This is to support parse stuff like "<http://foo.com>"
  let delimeterIndex;

  for (delimeterIndex = 0; delimeterIndex < rest.length; delimeterIndex++) {
    if (arrayIndexOf(delims, rest.charAt(delimeterIndex)) === -1) {
      break;
    }
  }

  if (delimeterIndex !== 0) {
    rest = rest.substr(delimeterIndex);
  }

  let proto = protocolPattern.exec(rest);
  let lowerProto;

  if (proto) {
    proto = proto[0];
    lowerProto = proto.toLowerCase();

    out.protocol = lowerProto;
    rest = rest.substr(proto.length);
  }

  // figure out if it's got a host
  // user@server is *always* interpreted as a hostname, and url
  // resolution will treat //foo/bar as host=foo,path=bar because that's
  // how the browser resolves relative URLs.
  let slashes;

  if (slashesDenoteHost || proto || rest.match(/^\/\/[^@/]+@[^@/]+/)) {
    slashes = rest.substr(0, 2) === '//';

    if (slashes && !(proto && hostlessProtocol[proto])) {
      rest = rest.substr(2);
      out.slashes = true;
    }
  }

  if (!hostlessProtocol[proto] &&
    (slashes || (proto && !slashedProtocol[proto]))) {
    // there's a hostname.
    // the first instance of /, ?, ;, or # ends the host.
    // don't enforce full RFC correctness, just be unstupid about it.

    // If there is an @ in the hostname, then non-host chars *are* allowed
    // to the left of the first @ sign, unless some non-auth character
    // comes *before* the @-sign.
    // URLs are obnoxious.
    const atSign = arrayIndexOf(rest, '@');

    if (atSign !== -1) {
      // there *may be* an auth
      let hasAuth = true;

      for (let i = 0; i < nonAuthChars.length; i++) {
        const index = arrayIndexOf(rest, nonAuthChars[i]);

        if (index !== -1 && index < atSign) {
          // not a valid auth.  Something like http://foo.com/bar@baz/
          hasAuth = false;
          break;
        }
      }
      if (hasAuth) {
        // pluck off the auth portion.
        out.auth = rest.substr(0, atSign);
        rest = rest.substr(atSign + 1);
      }
    }

    let firstNonHost = -1;

    for (let i = 0; i < nonHostChars.length; i++) {
      const index = arrayIndexOf(rest, nonHostChars[i]);

      if (index !== -1 && (firstNonHost < 0 || index < firstNonHost)) {
        firstNonHost = index;
      }
    }

    if (firstNonHost !== -1) {
      out.host = rest.substr(0, firstNonHost);
      rest = rest.substr(firstNonHost);
    } else {
      out.host = rest;
      rest = '';
    }

    // pull out port.
    const parsedHost = parseHost(out.host);
    const keys = Object.keys(parsedHost);

    for (let i = 0; i < keys.length; i++) {
      const key = keys[i];

      out[key] = parsedHost[key];
    }

    // we've indicated that there is a hostname,
    // so even if it's empty, it has to be present.
    out.hostname = out.hostname || '';

    // validate a little.
    if (out.hostname.length > hostnameMaxLen) {
      out.hostname = '';
    } else {
      const hostparts = out.hostname.split(/\./);

      for (let i = 0; i < hostparts.length; i++) {
        const part = hostparts[i];

        if (!part) {
          continue;
        }

        if (!part.match(hostnamePartPattern)) {
          let newpart = '';

          for (let j = 0; j < part.length; j++) {
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
            const validParts = hostparts.slice(0, i);
            const notHost = hostparts.slice(i + 1);
            const bit = part.match(hostnamePartStart);

            if (bit) {
              validParts.push(bit[1]);
              notHost.unshift(bit[2]);
            }

            if (notHost.length) {
              rest = `/${notHost.join('.')}${rest}`;
            }

            out.hostname = validParts.join('.');
            break;
          }
        }
      }
    }

    // hostnames are always lower case.
    out.hostname = out.hostname.toLowerCase();

    // IDNA Support: Returns a puny coded representation of "domain".
    // It only converts the part of the domain name that
    // has non ASCII characters. I.e. it dosent matter if
    // you call it with a domain that already is in ASCII.
    const domainArray = out.hostname.split('.');
    const newOut = [];

    for (let i = 0; i < domainArray.length; ++i) {
      const str = domainArray[i];

      newOut.push(str.match(/[^A-Za-z0-9_-]/) ? `xn--${punycode.encode(str)}` : str);
    }

    out.hostname = newOut.join('.');
    out.host = (out.hostname || '') + (out.port ? `:${out.port}` : '');
    out.href += out.host;
  }

  // now rest is set to the post-host stuff.
  // chop off any delim chars.
  if (!unsafeProtocol[lowerProto]) {
    // First, make 100% sure that any "autoEscape" chars get
    // escaped, even if encodeURIComponent doesn't think they
    // need to be.
    for (let i = 0; i < autoEscape.length; i++) {
      const ae = autoEscape[i];
      let esc = encodeURIComponent(ae);

      if (esc === ae) {
        esc = escape(ae);
      }

      rest = rest.split(ae).join(esc);
    }

    // Now make sure that delims never appear in a url.
    let chop = rest.length;

    for (let i = 0; i < delims.length; i++) {
      const cIndex = arrayIndexOf(rest, delims[i]);

      if (cIndex !== -1) {
        chop = Math.min(cIndex, chop);
      }
    }
    rest = rest.substr(0, chop);
  }

  // chop off from the tail first.
  const hash = arrayIndexOf(rest, '#');

  if (hash !== -1) {
    // got a fragment string.
    out.hash = rest.substr(hash);
    rest = rest.slice(0, hash);
  }

  const qm = arrayIndexOf(rest, '?');

  if (qm !== -1) {
    out.search = rest.substr(qm);
    out.query = rest.substr(qm + 1);

    if (parseQueryString) {
      out.query = querystring.parse(out.query);
    }

    rest = rest.slice(0, qm);
  } else if (parseQueryString) {
    // no query string, but parseQueryString still requested
    out.search = '';
    out.query = {};
  }

  if (rest) {
    out.pathname = rest;
  }

  if (slashedProtocol[proto] &&
    out.hostname && !out.pathname) {
    out.pathname = '/';
  }

  // to support http.request
  if (out.pathname || out.search) {
    out.path = (out.pathname ? out.pathname : '') +
      (out.search ? out.search : '');
  }

  // finally, reconstruct the href based on what has been validated.
  // eslint-disable-next-line no-use-before-define
  out.href = format(out);

  return out;
};

// format a parsed object into a url string
const format = obj => {
  // ensure it's an object, and not a string url.
  // If it's an obj, this is a no-op.
  // this way, you can call url_format() on strings
  // to clean up potentially wonky urls.
  if (typeof obj === 'string') {
    obj = parse(obj);
  }

  let auth = obj.auth || '';

  if (auth) {
    auth = auth.split('@').join('%40');

    for (let i = 0; i < nonAuthChars.length; i++) {
      const nAC = nonAuthChars[i];

      auth = auth.split(nAC).join(encodeURIComponent(nAC));
    }
    auth += '@';
  }

  let protocol = obj.protocol || '';

  const isHostDefined = obj.host !== undefined;
  const istHostnameDefined = obj.hostname !== undefined;
  let host;

  if (isHostDefined) {
    host = auth + obj.host;

    if (istHostnameDefined) {
      host = auth + obj.hostname + (obj.port ? `:${obj.port}` : '');
    }
  }

  let pathname = obj.pathname || '';
  const query = obj.query &&
      (typeof obj.query === 'object' &&
        Object.keys(obj.query).length ?
        querystring.stringify(obj.query) :
        '') || '';
  let search = obj.search || (query && `?${query}`) || '';
  let hash = obj.hash || '';

  if (protocol && protocol.substr(-1) !== ':') {
    protocol += ':';
  }

  // only the slashedProtocols get the //.  Not mailto:, xmpp:, etc.
  // unless they had them to begin with.
  if (obj.slashes ||
    (!protocol || slashedProtocol[protocol]) && host !== false) {
    host = `//${(host || '')}`;

    if (pathname && pathname.charAt(0) !== '/') {
      pathname = `/${pathname}`;
    }
  } else if (!host) {
    host = '';
  }

  if (hash && hash.charAt(0) !== '#') {
    hash = `#${hash}`;
  }

  if (search && search.charAt(0) !== '?') {
    search = `?${search}`;
  }

  return protocol + host + pathname + search + hash;
};

const resolveObject = (source, relative) => {
  if (!source) {
    return relative;
  }

  source = parse(format(source), false, true);
  relative = parse(format(relative), false, true);

  // hash is always overridden, no matter what.
  source.hash = relative.hash;

  if (relative.href === '') {
    source.href = format(source);

    return source;
  }

  // hrefs like //foo/bar always cut to the protocol.
  if (relative.slashes && !relative.protocol) {
    relative.protocol = source.protocol;

    // parse appends trailing / to urls like http://www.example.com
    if (slashedProtocol[relative.protocol] &&
      relative.hostname && !relative.pathname) {
      relative.path = relative.pathname = '/';
    }
    relative.href = format(relative);

    return relative;
  }

  if (relative.protocol && relative.protocol !== source.protocol) {
    // if it's a known url protocol, then changing
    // the protocol does weird things
    // first, if it's not file:, then we MUST have a host,
    // and if there was a path
    // to begin with, then we MUST have a path.
    // if it is file:, then the host is dropped,
    // because that's known to be hostless.
    // anything else is assumed to be absolute.
    if (!slashedProtocol[relative.protocol]) {
      relative.href = format(relative);

      return relative;
    }

    source.protocol = relative.protocol;

    if (!relative.host && !hostlessProtocol[relative.protocol]) {
      const relPath = (relative.pathname || '').split('/');

      // eslint-disable-next-line
      while (relPath.length && !(relative.host = relPath.shift()));

      if (!relative.host) {
        relative.host = '';
      }

      if (!relative.hostname) {
        relative.hostname = '';
      }

      if (relPath[0] !== '') {
        relPath.unshift('');
      }

      if (relPath.length < 2) {
        relPath.unshift('');
      }

      relative.pathname = relPath.join('/');
    }

    source.pathname = relative.pathname;
    source.search = relative.search;
    source.query = relative.query;
    source.host = relative.host || '';
    source.auth = relative.auth;
    source.hostname = relative.hostname || relative.host;
    source.port = relative.port;

    // to support http.request
    if (source.pathname !== undefined || source.search !== undefined) {
      source.path = (source.pathname ? source.pathname : '') +
        (source.search ? source.search : '');
    }

    source.slashes = source.slashes || relative.slashes;
    source.href = format(source);

    return source;
  }

  const isSourceAbs = source.pathname && source.pathname.charAt(0) === '/';
  const isRelAbs = relative.host !== undefined ||
      relative.pathname && relative.pathname.charAt(0) === '/';
  let mustEndAbs = isRelAbs || isSourceAbs || (source.host && relative.pathname);
  const removeAllDots = mustEndAbs;
  let srcPath = source.pathname && source.pathname.split('/') || [];
  const relPath = relative.pathname && relative.pathname.split('/') || [];
  const psychotic = source.protocol && !slashedProtocol[source.protocol];

  // if the url is a non-slashed url, then relative
  // links like ../.. should be able
  // to crawl up to the hostname, as well.  This is strange.
  // source.protocol has already been set by now.
  // Later on, put the first path part into the host field.
  if (psychotic) {
    // eslint-disable-next-line
    delete source.hostname;
    // eslint-disable-next-line
    delete source.port;

    if (source.host) {
      if (srcPath[0] === '') {
        srcPath[0] = source.host;
      } else {
        srcPath.unshift(source.host);
      }
    }
    // eslint-disable-next-line
    delete source.host;
    if (relative.protocol) {
      // eslint-disable-next-line
      delete relative.hostname;
      // eslint-disable-next-line
      delete relative.port;

      if (relative.host) {
        if (relPath[0] === '') {
          relPath[0] = relative.host;
        } else {
          relPath.unshift(relative.host);
        }
      }
      // eslint-disable-next-line
      delete relative.host;
    }

    mustEndAbs = mustEndAbs && (relPath[0] === '' || srcPath[0] === '');
  }

  if (isRelAbs) {
    // it's absolute.
    source.host = relative.host || relative.host === '' ?
      relative.host : source.host;
    source.hostname = relative.hostname || relative.hostname === '' ?
      relative.hostname : source.hostname;
    source.search = relative.search;
    source.query = relative.query;
    srcPath = relPath;

    // fall through to the dot-handling below.
  } else if (relPath.length) {
    // it's relative
    // throw away the existing file, and take the new path instead.
    if (!srcPath) {
      srcPath = [];
    }

    srcPath.pop();
    srcPath = srcPath.concat(relPath);
    source.search = relative.search;
    source.query = relative.query;
  } else if ('search' in relative) {
    // just pull out the search.
    // like href='?foo'.
    // Put this after the other two cases because it simplifies the booleans
    if (psychotic) {
      source.hostname = source.host = srcPath.shift();

      // occationaly the auth can get stuck only in host
      // this especialy happens in cases like
      // url.resolveObject('mailto:local1@domain1', 'local2@domain2')
      const authInHost = source.host && arrayIndexOf(source.host, '@') > 0 ?
        source.host.split('@') : false;

      if (authInHost) {
        source.auth = authInHost.shift();
        source.host = source.hostname = authInHost.shift();
      }
    }
    source.search = relative.search;
    source.query = relative.query;

    // to support http.request
    if (source.pathname !== undefined || source.search !== undefined) {
      source.path = (source.pathname ? source.pathname : '') +
        (source.search ? source.search : '');
    }
    source.href = format(source);

    return source;
  }

  if (!srcPath.length) {
    // no path at all.  easy.
    // we've already handled the other stuff above.
    // eslint-disable-next-line
    delete source.pathname;

    // to support http.request
    if (!source.search) {
      source.path = `/${source.search}`;
    } else {
      // eslint-disable-next-line
      delete source.path;
    }
    source.href = format(source);
    // eslint-disable-next-line
    return source;
  }

  // if a url ENDs in . or .., then it must get a trailing slash.
  // however, if it ends in anything else non-slashy,
  // then it must NOT get a trailing slash.
  let last = srcPath.slice(-1)[0];
  const hasTrailingSlash = (source.host || relative.host) && (last === '.' || last === '..') || last === '';

  // strip single dots, resolve double dots to parent dir
  // if the path tries to go above the root, `up` ends up > 0
  let up = 0;

  for (let i = srcPath.length; i >= 0; i--) {
    last = srcPath[i];

    if (last === '.') {
      srcPath.splice(i, 1);
    } else if (last === '..') {
      srcPath.splice(i, 1);
      // eslint-disable-next-line
      up++;
    } else if (up) {
      srcPath.splice(i, 1);
      // eslint-disable-next-line
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

  const isAbsolute = srcPath[0] === '' ||
    (srcPath[0] && srcPath[0].charAt(0) === '/');

  // put the host back
  if (psychotic) {
    if (isAbsolute) {
      source.host = '';
    } else if (srcPath.length) {
      source.host = srcPath.shift();
    } else {
      source.host = '';
    }

    source.hostname = source.host;

    // occationaly the auth can get stuck only in host
    // this especialy happens in cases like
    // url.resolveObject('mailto:local1@domain1', 'local2@domain2')
    const authInHost = source.host && arrayIndexOf(source.host, '@') > 0 ?
      source.host.split('@') : false;

    if (authInHost) {
      source.auth = authInHost.shift();
      source.host = source.hostname = authInHost.shift();
    }
  }

  mustEndAbs = mustEndAbs || (source.host && srcPath.length);

  if (mustEndAbs && !isAbsolute) {
    srcPath.unshift('');
  }

  source.pathname = srcPath.join('/');

  // to support request.http
  if (source.pathname !== undefined || source.search !== undefined) {
    source.path = (source.pathname ? source.pathname : '') +
      (source.search ? source.search : '');
  }
  source.auth = relative.auth || source.auth;
  source.slashes = source.slashes || relative.slashes;
  source.href = format(source);

  return source;
};

const resolve = (source, relative) => format(resolveObject(source, relative));

export {
  parse,
  resolve,
  resolveObject,
  format
};
