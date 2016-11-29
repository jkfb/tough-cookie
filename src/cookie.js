/*
 * Copyright (c) 2015, Salesforce.com, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of Salesforce.com nor the names of its contributors may
 * be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS 'AS IS'
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

import { getPublicSuffix } from './pubsuffix';
import { isIP } from './node-shim/net';
import { MemoryCookieStore } from './memstore';
import { pathMatch } from './pathMatch';
import { permuteDomain } from './permuteDomain';
import punycode from './third/punycode.es6';
import { Store } from './store';
import * as _URL from './node-shim/url';

// eslint-disable-next-line no-control-regex
const DATE_DELIM = /[\x09\x20-\x2F\x3B-\x40\x5B-\x60\x7B-\x7E]/;

// From RFC6265 S4.1.1
// note that it excludes \x3B ';'
const COOKIE_OCTET = /[\x21\x23-\x2B\x2D-\x3A\x3C-\x5B\x5D-\x7E]/;
const COOKIE_OCTETS = new RegExp(`^${COOKIE_OCTET.source}+$`);

// eslint-disable-next-line no-control-regex
const CONTROL_CHARS = /[\x00-\x1F]/;

// Double quotes are part of the value (see: S4.1.1).
// '\r', '\n' and '\0' should be treated as a terminator in the 'relaxed' mode
// (see: https://github.com/ChromiumWebApps/chromium/blob/b3d3b4da8bb94c1b2e061600df106d590fda3620/net/cookies/parsed_cookie.cc#L60)
// '=' and ';' are attribute/values separators
// (see: https://github.com/ChromiumWebApps/chromium/blob/b3d3b4da8bb94c1b2e061600df106d590fda3620/net/cookies/parsed_cookie.cc#L64)
const COOKIE_PAIR = /^(([^=;]+))\s*=\s*([^\n\r\0]*)/;

// Used to parse non-RFC-compliant cookies like '=abc' when given the `loose`
// option in Cookie.parse:
const LOOSE_COOKIE_PAIR = /^((?:=)?([^=;]*)\s*=\s*)?([^\n\r\0]*)/;

// RFC6265 S4.1.1 defines path value as 'any CHAR except CTLs or ';''
// Note ';' is \x3B
const PATH_VALUE = /[\x20-\x3A\x3C-\x7E]+/;

const DAY_OF_MONTH = /^(\d{1,2})[^\d]*$/;
const TIME = /^(\d{1,2})[^\d]*:(\d{1,2})[^\d]*:(\d{1,2})[^\d]*$/;
const MONTH = /^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)/i;

const MONTH_TO_NUM = {
  jan: 0,
  feb: 1,
  mar: 2,
  apr: 3,
  may: 4,
  jun: 5,
  jul: 6,
  aug: 7,
  sep: 8,
  oct: 9,
  nov: 10,
  dec: 11
};
const NUM_TO_MONTH = [
  'Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'
];
const NUM_TO_DAY = [
  'Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'
];

// 2 to 4 digits
const YEAR = /^(\d{2}|\d{4})$/;

// 31-bit max
const MAX_TIME = 2147483647000;

// 31-bit min
const MIN_TIME = 0;

// RFC6265 S5.1.1 date parser:
const parseDate = str => {
  if (!str) {
    return;
  }

  /* RFC6265 S5.1.1:
   * 2. Process each date-token sequentially in the order the date-tokens
   * appear in the cookie-date
   */
  const tokens = str.split(DATE_DELIM);

  if (!tokens) {
    return;
  }

  let hour = null;
  let minutes = null;
  let seconds = null;
  let day = null;
  let month = null;
  let year = null;

  for (let i = 0; i < tokens.length; i++) {
    const token = tokens[i].trim();

    if (!token.length) {
      continue;
    }

    let result;

    /* 2.1. If the found-time flag is not set and the token matches the time
     * production, set the found-time flag and set the hour- value,
     * minute-value, and second-value to the numbers denoted by the digits in
     * the date-token, respectively.  Skip the remaining sub-steps and continue
     * to the next date-token.
     */
    if (seconds === null) {
      result = TIME.exec(token);
      if (result) {
        hour = parseInt(result[1], 10);
        minutes = parseInt(result[2], 10);
        seconds = parseInt(result[3], 10);
        /* RFC6265 S5.1.1.5:
         * [fail if]
         * *  the hour-value is greater than 23,
         * *  the minute-value is greater than 59, or
         * *  the second-value is greater than 59.
         */
        if (hour > 23 || minutes > 59 || seconds > 59) {
          return;
        }

        continue;
      }
    }

    /* 2.2. If the found-day-of-month flag is not set and the date-token matches
     * the day-of-month production, set the found-day-of- month flag and set
     * the day-of-month-value to the number denoted by the date-token.  Skip
     * the remaining sub-steps and continue to the next date-token.
     */
    if (day === null) {
      result = DAY_OF_MONTH.exec(token);
      if (result) {
        day = parseInt(result, 10);
        /* RFC6265 S5.1.1.5:
         * [fail if] the day-of-month-value is less than 1 or greater than 31
         */
        if (day < 1 || day > 31) {
          return;
        }
        continue;
      }
    }

    /* 2.3. If the found-month flag is not set and the date-token matches the
     * month production, set the found-month flag and set the month-value to
     * the month denoted by the date-token.  Skip the remaining sub-steps and
     * continue to the next date-token.
     */
    if (month === null) {
      result = MONTH.exec(token);
      if (result) {
        month = MONTH_TO_NUM[result[1].toLowerCase()];
        continue;
      }
    }

    /* 2.4. If the found-year flag is not set and the date-token matches the year
     * production, set the found-year flag and set the year-value to the number
     * denoted by the date-token.  Skip the remaining sub-steps and continue to
     * the next date-token.
     */
    if (year === null) {
      result = YEAR.exec(token);
      if (result) {
        year = parseInt(result[0], 10);
        /* From S5.1.1:
         * 3.  If the year-value is greater than or equal to 70 and less
         * than or equal to 99, increment the year-value by 1900.
         * 4.  If the year-value is greater than or equal to 0 and less
         * than or equal to 69, increment the year-value by 2000.
         */
        if (year >= 70 && year <= 99) {
          year += 1900;
        } else if (year >= 0 && year <= 69) {
          year += 2000;
        }

        // 5. ... the year-value is less than 1601
        if (year < 1601) {
          return;
        }
      }
    }
  }

  // 5. ... at least one of the found-day-of-month, found-month, found-
  // year, or found-time flags is not set,
  if (seconds === null || day === null || month === null || year === null) {
    return;
  }

  return new Date(Date.UTC(year, month, day, hour, minutes, seconds));
};

const formatDate = date => {
  let uDate = date.getUTCDate();
  let hours = date.getUTCHours();
  let minutes = date.getUTCMinutes();
  let seconds = date.getUTCSeconds();

  uDate = uDate >= 10 ? uDate : `0${uDate}`;
  hours = hours >= 10 ? hours : `0${hours}`;
  minutes = minutes >= 10 ? minutes : `0${minutes}`;
  seconds = seconds >= 10 ? seconds : `0${seconds}`;

  return `${NUM_TO_DAY[date.getUTCDay()]}, ${uDate} ${NUM_TO_MONTH[date.getUTCMonth()]} ${date.getUTCFullYear()}
    ${hours}:${minutes}:${seconds} GMT`;
};

// S5.1.2 Canonicalized Host Names
const canonicalDomain = str => {
  if (str == null) { // eslint-disable-line
    return null;
  }

  // S4.1.2.3 & S5.2.3: ignore leading .
  str = str.trim().replace(/^\./, '');

  // convert to IDN if any non-ASCII characters
  if (punycode && /[^\u0001-\u007f]/.test(str)) {
    str = punycode.toASCII(str);
  }

  return str.toLowerCase();
};

// S5.1.3 Domain Matching
const domainMatch = (str, domStr, canonicalize) => {
  if (str == null || domStr == null) { // eslint-disable-line
    return null;
  }

  if (canonicalize !== false) {
    str = canonicalDomain(str);
    domStr = canonicalDomain(domStr);
  }

  /*
   * The domain string and the string are identical. (Note that both the
   * domain string and the string will have been canonicalized to lower case at
   * this point)
   */
  if (str === domStr) {
    return true;
  }

  // All of the following [three] conditions hold: (order adjusted from the RFC)

  // The string is a host name (i.e., not an IP address).
  if (isIP(str)) {
    return false;
  }

  // The domain string is a suffix of the string
  const idx = str.indexOf(domStr);

  if (idx <= 0) {
    // it's a non-match (-1) or prefix (0)
    return false;
  }

  // e.g 'a.b.c'.indexOf('b.c') === 2
  // 5 === 3+2
  // it's not a suffix
  if (str.length !== domStr.length + idx) {
    return false;
  }

  // The last character of the string that is not included in the domain
  // string is a %x2E ('.') character.
  if (str.substr(idx - 1, 1) !== '.') {
    return false;
  }

  return true;
};

// RFC6265 S5.1.4 Paths and Path-Match
/*
 * The user agent MUST use an algorithm equivalent to the following algorithm
 * to compute the default-path of a cookie:
 *
 * Assumption: the path (and not query part or absolute uri) is passed in.
 */
const defaultPath = path => {
  // 2. If the uri-path is empty or if the first character of the uri-path is not
  // a %x2F ('/') character, output %x2F ('/') and skip the remaining steps.
  if (!path || path.substr(0, 1) !== '/') {
    return '/';
  }

  // 3. If the uri-path contains no more than one %x2F ('/') character, output
  // %x2F ('/') and skip the remaining step.
  if (path === '/') {
    return path;
  }

  const rightSlash = path.lastIndexOf('/');

  if (rightSlash === 0) {
    return '/';
  }

  // 4. Output the characters of the uri-path from the first character up to,
  // but not including, the right-most %x2F ('/').
  return path.slice(0, rightSlash);
};

const parse = (str, options) => {
  if (!options || typeof options !== 'object') {
    options = {};
  }
  str = str.trim();

  // We use a regex to parse the 'name-value-pair' part of S5.2
  // S5.2 step 1
  const firstSemi = str.indexOf(';');
  const pairRe = options.loose ? LOOSE_COOKIE_PAIR : COOKIE_PAIR;
  const result = pairRe.exec(firstSemi === -1 ? str : str.substr(0, firstSemi));

  // Rx satisfies the 'the name string is empty' and 'lacks a %x3D ('=')'
  // constraints as well as trimming any whitespace.
  if (!result) {
    return;
  }

  // eslint-disable-next-line no-use-before-define
  const cookie = new Cookie();

  if (result[1]) {
    cookie.key = result[2].trim();
  } else {
    cookie.key = '';
  }
  cookie.value = result[3].trim();
  if (CONTROL_CHARS.test(cookie.key) || CONTROL_CHARS.test(cookie.value)) {
    return;
  }

  if (firstSemi === -1) {
    return cookie;
  }

  // S5.2.3 unparsed-attributes consist of the remainder of the set-cookie-string
  // (including the %x3B (';') in question). plus later on in the same section
  // discard the first ';' and trim.
  const unparsed = str.slice(firstSemi + 1).trim();

  // If the unparsed-attributes string is empty, skip the rest of these
  // steps.
  if (unparsed.length === 0) {
    return cookie;
  }

  /*
   * S5.2 says that when looping over the items '[p]rocess the attribute-name
   * and attribute-value according to the requirements in the following
   * subsections' for every item.  Plus, for many of the individual attributes
   * in S5.3 it says to use the 'attribute-value of the last attribute in the
   * cookie-attribute-list'.  Therefore, in this implementation, we overwrite
   * the previous value.
   */
  const cookieAvs = unparsed.split(';');

  while (cookieAvs.length) {
    const av = cookieAvs.shift().trim();

    // happens if ';;' appears
    if (av.length === 0) {
      continue;
    }

    const avSep = av.indexOf('=');
    let avKey;
    let avValue;

    if (avSep === -1) {
      avKey = av;
      avValue = null;
    } else {
      avKey = av.substr(0, avSep);
      avValue = av.substr(avSep + 1);
    }

    avKey = avKey.trim().toLowerCase();

    if (avValue) {
      avValue = avValue.trim();
    }

    switch (avKey) {

      // S5.2.1
      case 'expires':
        if (avValue) {
          const exp = parseDate(avValue);

          // If the attribute-value failed to parse as a cookie date, ignore the
          // cookie-av.
          if (exp) {
            // over and underflow not realistically a concern: V8's getTime() seems to
            // store something larger than a 32-bit time_t (even with 32-bit node)
            cookie.expires = exp;
          }
        }
        break;

      // S5.2.2
      case 'max-age':
        if (avValue) {
          // If the first character of the attribute-value is not a DIGIT or a '-'
          // character ...[or]... If the remainder of attribute-value contains a
          // non-DIGIT character, ignore the cookie-av.
          if (/^-?[0-9]+$/.test(avValue)) {
            const delta = parseInt(avValue, 10);

            // If delta-seconds is less than or equal to zero (0), let expiry-time
            // be the earliest representable date and time.
            cookie.setMaxAge(delta);
          }
        }
        break;

      // S5.2.3
      case 'domain':
        // If the attribute-value is empty, the behavior is undefined. However,
        // the user agent SHOULD ignore the cookie-av entirely.
        if (avValue) {
          // S5.2.3 Let cookie-domain be the attribute-value without the leading %x2E
          // ('.') character.
          const domain = avValue.trim().replace(/^\./, '');

          if (domain) {
            // Convert the cookie-domain to lower case.
            cookie.domain = domain.toLowerCase();
          }
        }
        break;

      // S5.2.4
      case 'path':
        /*
        * If the attribute-value is empty or if the first character of the
        * attribute-value is not %x2F ('/'):
        *   Let cookie-path be the default-path.
        * Otherwise:
        *   Let cookie-path be the attribute-value.
        *
        * We'll represent the default-path as null since it depends on the
        * context of the parsing.
        */
        cookie.path = avValue && avValue[0] === '/' ? avValue : null;
        break;

      // S5.2.5
      case 'secure':
        /*
        * If the attribute-name case-insensitively matches the string 'Secure',
        * the user agent MUST append an attribute to the cookie-attribute-list
        * with an attribute-name of Secure and an empty attribute-value.
        */
        cookie.secure = true;
        break;

      // S5.2.6 -- effectively the same as 'secure'
      case 'httponly':
        cookie.httpOnly = true;
        break;

      default:
        cookie.extensions = cookie.extensions || [];
        cookie.extensions.push(av);
        break;
    }
  }

  return cookie;
};

// avoid the V8 deoptimization monster!
const jsonParse = str => {
  let obj;

  try {
    obj = JSON.parse(str);
  } catch (error) {
    return error;
  }

  return obj;
};

const fromJSON = str => {
  if (!str) {
    return null;
  }

  let obj;

  if (typeof str === 'string') {
    obj = jsonParse(str);
    if (obj instanceof Error) {
      return null;
    }
  } else {
    // assume it's an Object
    obj = str;
  }

  // eslint-disable-next-line no-use-before-define
  const cookie = new Cookie();

  for (let i = 0; i < Cookie.serializableProperties.length; i++) {
    // eslint-disable-next-line no-use-before-define
    const prop = Cookie.serializableProperties[i];

    // leave as prototype default
    if (obj[prop] === undefined ||
        obj[prop] === Cookie.prototype[prop]) { // eslint-disable-line no-use-before-define
      continue;
    }

    if (prop === 'expires' ||
        prop === 'creation' ||
        prop === 'lastAccessed') {
      if (obj[prop] === null) {
        cookie[prop] = null;
      } else {
        // eslint-disable-next-line
        cookie[prop] = obj[prop] == 'Infinity' ?
          'Infinity' : new Date(obj[prop]);
      }
    } else {
      cookie[prop] = obj[prop];
    }
  }

  return cookie;
};

/* Section 5.4 part 2:
 *  *  Cookies with longer paths are listed before cookies with
 *     shorter paths.
 *
 *  *  Among cookies that have equal-length path fields, cookies with
 *     earlier creation-times are listed before cookies with later
 *     creation-times.
 */

const cookieCompare = (objA, objB) => {
  let cmp = 0;

  // descending for length: b CMP a
  const aPathLen = objA.path ? objA.path.length : 0;
  const bPathLen = objB.path ? objB.path.length : 0;

  cmp = bPathLen - aPathLen;

  if (cmp !== 0) {
    return cmp;
  }

  // ascending for time: a CMP b
  const aTime = objA.creation ? objA.creation.getTime() : MAX_TIME;
  const bTime = objB.creation ? objB.creation.getTime() : MAX_TIME;

  cmp = aTime - bTime;

  if (cmp !== 0) {
    return cmp;
  }

  // break ties for the same millisecond (precision of JavaScript's clock)
  cmp = objA.creationIndex - objB.creationIndex;

  return cmp;
};

// Gives the permutation of all possible pathMatch()es of a given path. The
// array is in longest-to-shortest order. Handy for indexing.
const permutePath = path => {
  if (path === '/') {
    return [ '/' ];
  }

  if (path.lastIndexOf('/') === (path.length - 1)) {
    path = path.substr(0, path.length - 1);
  }

  const permutations = [ path ];

  while (path.length > 1) {
    const lindex = path.lastIndexOf('/');

    if (lindex === 0) {
      break;
    }

    path = path.substr(0, lindex);
    permutations.push(path);
  }

  permutations.push('/');

  return permutations;
};

const getCookieContext = url => {
  if (url instanceof Object) {
    return url;
  }

  // NOTE: decodeURI will throw on malformed URIs (see GH-32).
  // Therefore, we will just skip decoding for such URIs.
  try {
    url = decodeURI(url);
  } catch (err) {
    // Silently swallow error
  }

  return _URL.parse(url);
};

const Cookie = function (options = {}) {
  Object.keys(options).forEach(prop => {
    if (Cookie.prototype.hasOwnProperty(prop) &&
        Cookie.prototype[prop] !== options[prop] &&
        prop.substr(0, 1) !== '_') {
      this[prop] = options[prop];
    }
  }, this);

  this.creation = this.creation || new Date();

  // used to break creation ties in cookieCompare():
  // eslint-disable-next-line
  Object.defineProperty(this, 'creationIndex', {
    configurable: false,
    // eslint-disable-next-line
    enumerable: false, // important for assert.deepEqual checks
    writable: true,
    value: ++Cookie.cookiesCreated // eslint-disable-line
  });
};

// incremented each time a cookie is created
Cookie.cookiesCreated = 0;

Cookie.parse = parse;
Cookie.fromJSON = fromJSON;

Cookie.prototype.key = '';
Cookie.prototype.value = '';

// the order in which the RFC has them:
// coerces to literal Infinity
Cookie.prototype.expires = 'Infinity';

// takes precedence over expires for TTL
Cookie.prototype.maxAge = null;
Cookie.prototype.domain = null;
Cookie.prototype.path = null;
Cookie.prototype.secure = false;
Cookie.prototype.httpOnly = false;
Cookie.prototype.extensions = null;

// set by the CookieJar:

// boolean when set
Cookie.prototype.hostOnly = null;

// boolean when set
Cookie.prototype.pathIsDefault = null;

// Date when set; defaulted by Cookie.parse
Cookie.prototype.creation = null;

// Date when set
Cookie.prototype.lastAccessed = null;
// eslint-disable-next-line
Object.defineProperty(Cookie.prototype, 'creationIndex', {
  configurable: true,
  enumerable: false,
  writable: true,
  value: 0
});

Cookie.serializableProperties = Object.keys(Cookie.prototype)
  .filter(prop =>
    !(
      Cookie.prototype[prop] instanceof Function ||
      prop === 'creationIndex' ||
      prop.substr(0, 1) === '_'
    )
  );

Cookie.prototype.inspect = function inspect () {
  const now = Date.now();
  const hostOnly = this.hostOnly != null ? this.hostOnly : '?'; // eslint-disable-line
  const aAge = this.lastAccessed ? `${now - this.lastAccessed.getTime()}ms` : '?';
  const cAge = this.creation ? `${now - this.creation.getTime()}ms` : '?';

  return `Cookie="${this.toString()}; hostOnly=${hostOnly}; aAge=${aAge}; cAge=${cAge}"`;
};

Cookie.prototype.toJSON = function () {
  const obj = {};
  const props = Cookie.serializableProperties;

  for (let i = 0; i < props.length; i++) {
    const prop = props[i];

    // leave as prototype default
    if (this[prop] === Cookie.prototype[prop]) {
      continue;
    }

    if (prop === 'expires' ||
        prop === 'creation' ||
        prop === 'lastAccessed') {
      if (this[prop] === null) {
        obj[prop] = null;
      } else {
        // eslint-disable-next-line
        obj[prop] = this[prop] == 'Infinity' ? // intentionally not ===
          'Infinity' : this[prop].toISOString();
      }
    } else if (prop === 'maxAge') {
      if (this[prop] !== null) {
        // again, intentionally not ===
        obj[prop] = this[prop] == Infinity || this[prop] == -Infinity ? // eslint-disable-line
          this[prop].toString() : this[prop];
      }
    } else if (this[prop] !== Cookie.prototype[prop]) {
      obj[prop] = this[prop];
    }
  }

  return obj;
};

Cookie.prototype.clone = function () {
  return fromJSON(this.toJSON());
};

Cookie.prototype.validate = function validate () {
  if (!COOKIE_OCTETS.test(this.value)) {
    return false;
  }

  if (this.expires != Infinity && !(this.expires instanceof Date) && !parseDate(this.expires)) { // eslint-disable-line
    return false;
  }

  if (this.maxAge != null && this.maxAge <= 0) { // eslint-disable-line
    // 'Max-Age=' non-zero-digit *DIGIT
    return false;
  }

  if (this.path != null && !PATH_VALUE.test(this.path)) { // eslint-disable-line
    return false;
  }

  const cdomain = this.cdomain();

  if (cdomain) {
    if (cdomain.match(/\.$/)) {
      // S4.1.2.3 suggests that this is bad. domainMatch() tests confirm this
      return false;
    }
    const suffix = getPublicSuffix(cdomain);

    // it's a public suffix
    if (suffix == null) { // eslint-disable-line
      return false;
    }
  }

  return true;
};

Cookie.prototype.setExpires = function setExpires (exp) {
  if (exp instanceof Date) {
    this.expires = exp;
  } else {
    this.expires = parseDate(exp) || 'Infinity';
  }
};

Cookie.prototype.setMaxAge = function setMaxAge (age) {
  if (age === Infinity || age === -Infinity) {
    // so JSON.stringify() works
    this.maxAge = age.toString();
  } else {
    this.maxAge = age;
  }
};

// gives Cookie header format
Cookie.prototype.cookieString = function cookieString () {
  let val = this.value;

  if (val == null) { // eslint-disable-line
    val = '';
  }

  if (this.key === '') {
    return val;
  }

  return `${this.key}=${val}`;
};

// gives Set-Cookie header format
Cookie.prototype.toString = function toString () {
  let str = this.cookieString();

  if (this.expires != Infinity) { // eslint-disable-line
    if (this.expires instanceof Date) {
      str += `; Expires=${formatDate(this.expires)}`;
    } else {
      str += `; Expires=${this.expires}`;
    }
  }

  if (this.maxAge != null && this.maxAge != Infinity) { // eslint-disable-line
    str += `; Max-Age=${this.maxAge}`;
  }

  if (this.domain && !this.hostOnly) {
    str += `; Domain=${this.domain}`;
  }

  if (this.path) {
    str += `; Path=${this.path}`;
  }

  if (this.secure) {
    str += '; Secure';
  }

  if (this.httpOnly) {
    str += '; HttpOnly';
  }

  if (this.extensions) {
    this.extensions.forEach(ext => {
      str += `; ${ext}`;
    });
  }

  return str;
};

// TTL() partially replaces the 'expiry-time' parts of S5.3 step 3 (setCookie()
// elsewhere)
// S5.3 says to give the 'latest representable date' for which we use Infinity
// For 'expired' we use 0
Cookie.prototype.TTL = function TTL (now) {
  /* RFC6265 S4.1.2.2 If a cookie has both the Max-Age and the Expires
   * attribute, the Max-Age attribute has precedence and controls the
   * expiration date of the cookie.
   * (Concurs with S5.3 step 3)
   */
  if (this.maxAge != null) { // eslint-disable-line
    return this.maxAge <= 0 ? 0 : this.maxAge * 1000;
  }

  let expires = this.expires;

  if (expires != Infinity) { // eslint-disable-line
    if (!(expires instanceof Date)) {
      expires = parseDate(expires) || Infinity;
    }

    if (expires == Infinity) { // eslint-disable-line
      return Infinity;
    }

    return expires.getTime() - (now || Date.now());
  }

  return Infinity;
};

// expiryTime() replaces the 'expiry-time' parts of S5.3 step 3 (setCookie()
// elsewhere)
Cookie.prototype.expiryTime = function expiryTime (now) {
  if (this.maxAge != null) { // eslint-disable-line
    const relativeTo = now || this.creation || new Date();
    const age = this.maxAge <= 0 ? -Infinity : this.maxAge * 1000;

    return relativeTo.getTime() + age;
  }

  if (this.expires == Infinity) { // eslint-disable-line
    return Infinity;
  }

  return this.expires.getTime();
};

// expiryDate() replaces the 'expiry-time' parts of S5.3 step 3 (setCookie()
// elsewhere), except it returns a Date
Cookie.prototype.expiryDate = function expiryDate (now) {
  const millisec = this.expiryTime(now);

  if (millisec == Infinity) { // eslint-disable-line
    return new Date(MAX_TIME);
  } else if (millisec == -Infinity) { // eslint-disable-line
    return new Date(MIN_TIME);
  }

  return new Date(millisec);
};

// This replaces the 'persistent-flag' parts of S5.3 step 3
Cookie.prototype.isPersistent = function isPersistent () {
  return this.maxAge != null || this.expires != Infinity; // eslint-disable-line
};

// Mostly S5.1.2 and S5.2.3:
Cookie.prototype.cdomain =
Cookie.prototype.canonicalizedDomain = function canonicalizedDomain () {
  if (this.domain == null) { // eslint-disable-line
    return null;
  }

  return canonicalDomain(this.domain);
};

const CookieJar = function (store, options) {
  if (typeof options === 'boolean') {
    options = { rejectPublicSuffixes: options };
  } else if (options === undefined || options === null) {
    options = {};
  }

  if (options.rejectPublicSuffixes != null) { // eslint-disable-line
    this.rejectPublicSuffixes = options.rejectPublicSuffixes;
  }

  if (options.looseMode != null) { // eslint-disable-line
    this.enableLooseMode = options.looseMode;
  }

  if (!store) {
    store = new MemoryCookieStore();
  }

  this.store = store;
};

CookieJar.prototype.store = null;
CookieJar.prototype.rejectPublicSuffixes = true;
CookieJar.prototype.enableLooseMode = false;

const CAN_BE_SYNC = [];

CAN_BE_SYNC.push('setCookie');
CookieJar.prototype.setCookie = function (cookie, url, options, cb) {
  let err;
  const context = getCookieContext(url);

  if (options instanceof Function) {
    cb = options;
    options = {};
  }

  const host = canonicalDomain(context.hostname);
  let loose = this.enableLooseMode;

  if (options.loose != null) { // eslint-disable-line
    loose = options.loose;
  }

  // S5.3 step 1
  if (!(cookie instanceof Cookie)) {
    cookie = Cookie.parse(cookie, { loose });
  }

  if (!cookie) {
    err = new Error('Cookie failed to parse');

    return cb(options.ignoreError ? null : err);
  }

  // S5.3 step 2
  // will assign later to save effort in the face of errors
  const now = options.now || new Date();

  // S5.3 step 3: NOOP; persistent-flag and expiry-time is handled by getCookie()

  // S5.3 step 4: NOOP; domain is null by default

  // S5.3 step 5: public suffixes
  if (this.rejectPublicSuffixes && cookie.domain) {
    const suffix = getPublicSuffix(cookie.cdomain());

    // e.g. 'com'
    if (suffix == null) { // eslint-disable-line
      err = new Error('Cookie has domain set to a public suffix');

      return cb(options.ignoreError ? null : err);
    }
  }

  // S5.3 step 6:
  if (cookie.domain) {
    if (!domainMatch(host, cookie.cdomain(), false)) {
      err = new Error(`Cookie not in this host's domain. Cookie:${cookie.cdomain()} Request:${host}`);

      return cb(options.ignoreError ? null : err);
    }

    // don't reset if already set
    if (cookie.hostOnly == null) { // eslint-disable-line
      cookie.hostOnly = false;
    }
  } else {
    cookie.hostOnly = true;
    cookie.domain = host;
  }

  // S5.2.4 If the attribute-value is empty or if the first character of the
  // attribute-value is not %x2F ('/'):
  // Let cookie-path be the default-path.
  if (!cookie.path || cookie.path[0] !== '/') {
    cookie.path = defaultPath(context.pathname);
    cookie.pathIsDefault = true;
  }

  // S5.3 step 8: NOOP; secure attribute
  // S5.3 step 9: NOOP; httpOnly attribute

  // S5.3 step 10
  if (options.http === false && cookie.httpOnly) {
    err = new Error(`Cookie is HttpOnly and this isn't an HTTP API`);

    return cb(options.ignoreError ? null : err);
  }

  const store = this.store;

  if (!store.updateCookie) {
    store.updateCookie = function (oldCookie, newCookie, callback) {
      this.putCookie(newCookie, callback);
    };
  }

  const withCookie = (error, oldCookie) => {
    if (error) {
      return cb(error);
    }

    const next = er => {
      if (er) {
        return cb(er);
      }
      cb(null, cookie);
    };

    if (oldCookie) {
      // S5.3 step 11 - 'If the cookie store contains a cookie with the same name,
      // domain, and path as the newly created cookie:'
      // step 11.2
      if (options.http === false && oldCookie.httpOnly) {
        error = new Error(`old Cookie is HttpOnly and this isn't an HTTP API`);

        return cb(options.ignoreError ? null : error);
      }

      // step 11.3
      cookie.creation = oldCookie.creation;

      // preserve tie-breaker
      cookie.creationIndex = oldCookie.creationIndex;
      cookie.lastAccessed = now;

      // Step 11.4 (delete cookie) is implied by just setting the new one:
      // step 12
      store.updateCookie(oldCookie, cookie, next);
    } else {
      cookie.creation = cookie.lastAccessed = now;

      // step 12
      store.putCookie(cookie, next);
    }
  };

  store.findCookie(cookie.domain, cookie.path, cookie.key, withCookie);
};

// RFC6365 S5.4
CAN_BE_SYNC.push('getCookies');
CookieJar.prototype.getCookies = function (url, options, cb) {
  const context = getCookieContext(url);

  if (options instanceof Function) {
    cb = options;
    options = {};
  }

  const host = canonicalDomain(context.hostname);
  const path = context.pathname || '/';

  let secure = options.secure;

  if (secure == null && context.protocol && // eslint-disable-line
      (context.protocol == 'https:' || context.protocol == 'wss:')) { // eslint-disable-line
    secure = true;
  }

  let http = options.http;

  if (http == null) { // eslint-disable-line
    http = true;
  }

  const now = options.now || Date.now();
  const expireCheck = options.expire !== false;
  const allPaths = Boolean(options.allPaths);
  const store = this.store;

  const matchingCookie = cookie => {
    // 'Either:
    //   The cookie's host-only-flag is true and the canonicalized
    //   request-host is identical to the cookie's domain.
    // Or:
    //   The cookie's host-only-flag is false and the canonicalized
    //   request-host domain-matches the cookie's domain.'
    if (cookie.hostOnly) {
      if (cookie.domain != host) { // eslint-disable-line
        return false;
      }
    } else if (!domainMatch(host, cookie.domain, false)) {
      return false;
    }

    // 'The request-uri's path path-matches the cookie's path.'
    if (!allPaths && !pathMatch(path, cookie.path)) {
      return false;
    }

    // 'If the cookie's secure-only-flag is true, then the request-uri's
    // scheme must denote a 'secure' protocol'
    if (cookie.secure && !secure) {
      return false;
    }

    // 'If the cookie's http-only-flag is true, then exclude the cookie if the
    // cookie-string is being generated for a 'non-HTTP' API'
    if (cookie.httpOnly && !http) {
      return false;
    }

    // deferred from S5.3
    // non-RFC: allow retention of expired cookies by choice
    if (expireCheck && cookie.expiryTime() <= now) {
      // result ignored
      // eslint-disable-next-line
      store.removeCookie(cookie.domain, cookie.path, cookie.key, () => {});

      return false;
    }

    return true;
  };

  store.findCookies(host, allPaths ? null : path, (err, cookies) => {
    if (err) {
      return cb(err);
    }

    cookies = cookies.filter(matchingCookie);

    // sorting of S5.4 part 2
    if (options.sort !== false) {
      cookies = cookies.sort(cookieCompare);
    }

    // S5.4 part 3
    const currentDate = new Date();

    cookies.forEach(theCookie => {
      theCookie.lastAccessed = currentDate;
    });

    cb(null, cookies);
  });
};

CAN_BE_SYNC.push('getCookieString');
CookieJar.prototype.getCookieString = function (...args) {
  const cb = args.pop();
  const next = (err, cookies) => {
    if (err) {
      cb(err);
    } else {
      cb(null, cookies
        .sort(cookieCompare)
        .map(cookie => cookie.cookieString())
        .join('; '));
    }
  };

  args.push(next);
  // eslint-disable-next-line
  this.getCookies.apply(this, args);
};

CAN_BE_SYNC.push('getSetCookieStrings');
CookieJar.prototype.getSetCookieStrings = function (...args) {
  const cb = args.pop();
  const next = (err, cookies) => {
    if (err) {
      cb(err);
    } else {
      cb(null, cookies.map(cookie => cookie.toString()));
    }
  };

  args.push(next);
  // eslint-disable-next-line
  this.getCookies.apply(this, args);
};

CAN_BE_SYNC.push('serialize');
CookieJar.prototype.serialize = function (cb) {
  let type = this.store.constructor.name;

  if (type === 'Object') {
    type = null;
  }

  // update README.md 'Serialization Format' if you change this, please!
  const serialized = {

    // add the store type, to make humans happy:
    storeType: type,

    // CookieJar configuration:
    rejectPublicSuffixes: Boolean(this.rejectPublicSuffixes),

    // this gets filled from getAllCookies:
    cookies: []
  };

  if (!(this.store.getAllCookies &&
        typeof this.store.getAllCookies === 'function')) {
    return cb(new Error('store does not support getAllCookies and cannot be serialized'));
  }

  this.store.getAllCookies((err, cookies) => {
    if (err) {
      return cb(err);
    }

    serialized.cookies = cookies.map(cookie => {
      // convert to serialized 'raw' cookies
      cookie = cookie instanceof Cookie ? cookie.toJSON() : cookie;

      // Remove the index so new ones get assigned during deserialization
      // eslint-disable-next-line
      delete cookie.creationIndex;

      return cookie;
    });

    return cb(null, serialized);
  });
};

// well-known name that JSON.stringify calls
CookieJar.prototype.toJSON = function () {
  return this.serializeSync();
};

// use the class method CookieJar.deserialize instead of calling this directly
CAN_BE_SYNC.push('importCookies');
CookieJar.prototype.importCookies = function (serialized, cb) {
  // eslint-disable-next-line consistent-this
  const jar = this;
  let cookies = serialized.cookies;

  if (!cookies || !Array.isArray(cookies)) {
    return cb(new Error('serialized jar has no cookies array'));
  }

  // do not modify the original
  cookies = cookies.slice();

  const putNext = err => {
    if (err) {
      return cb(err);
    }

    if (!cookies.length) {
      return cb(err, jar);
    }

    let cookie;

    try {
      cookie = fromJSON(cookies.shift());
    } catch (error) {
      return cb(error);
    }

    if (cookie === null) {
      // skip this cookie
      return putNext(null);
    }

    jar.store.putCookie(cookie, putNext);
  };

  putNext();
};

CookieJar.deserialize = function (...args) {
  const strOrObj = args[0];
  let store = args[1];
  let cb = args[2];

  if (args.length < 3) {
    cb = store;
    store = null;
  }

  let serialized;

  if (typeof strOrObj === 'string') {
    serialized = jsonParse(strOrObj);

    if (serialized instanceof Error) {
      return cb(serialized);
    }
  } else {
    serialized = strOrObj;
  }

  const jar = new CookieJar(store, serialized.rejectPublicSuffixes);

  jar.importCookies(serialized, err => {
    if (err) {
      return cb(err);
    }
    cb(null, jar);
  });
};

CookieJar.deserializeSync = function (strOrObj, store) {
  const serialized = typeof strOrObj === 'string' ?
    JSON.parse(strOrObj) : strOrObj;
  const jar = new CookieJar(store, serialized.rejectPublicSuffixes);

  // catch this mistake early:
  if (!jar.store.synchronous) {
    throw new Error('CookieJar store is not synchronous; use async API instead.');
  }

  jar.importCookiesSync(serialized);

  return jar;
};
CookieJar.fromJSON = CookieJar.deserializeSync;

CAN_BE_SYNC.push('clone');
CookieJar.prototype.clone = function (...args) {
  let newStore = args[0];
  let cb = args[1];

  if (args.length === 1) {
    cb = newStore;
    newStore = null;
  }

  this.serialize((err, serialized) => {
    if (err) {
      return cb(err);
    }
    CookieJar.deserialize(newStore, serialized, cb);
  });
};

// Use a closure to provide a true imperative API for synchronous stores.
const syncWrap = method => function (...args) {
  if (!this.store.synchronous) {
    throw new Error('CookieJar store is not synchronous; use async API instead.');
  }

  let syncErr;
  let syncResult;

  args.push((err, result) => {
    syncErr = err;
    syncResult = result;
  });

  // eslint-disable-next-line
  this[method].apply(this, args);

  if (syncErr) {
    throw syncErr;
  }

  return syncResult;
};

// wrap all declared CAN_BE_SYNC methods in the sync wrapper
CAN_BE_SYNC.forEach(method => {
  CookieJar.prototype[`${method}Sync`] = syncWrap(method);
});

module.exports = {
  CookieJar,
  Cookie,
  Store,
  MemoryCookieStore,
  parseDate,
  formatDate,
  parse,
  fromJSON,
  domainMatch,
  defaultPath,
  pathMatch,
  getPublicSuffix,
  cookieCompare,
  permuteDomain,
  permutePath,
  canonicalDomain
};
