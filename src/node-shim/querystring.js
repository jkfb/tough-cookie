/*
 * "Forked" from https://github.com/stagas/node-shim/blob/master/lib/querystring.js
 * Should be MIT licenced
 */

/*
 * querystring
 * Copyright(c) 2010 TJ Holowaychuk <tj@vision-media.ca>
 * MIT Licensed
 */

/**
 * Library version.
 */
const version = '0.4.0';

/**
 * Object#toString() ref for stringify().
 */
const toString = Object.prototype.toString;

/**
 * Cache non-integer test regexp.
 */
const notint = /[^0-9]/;

/**
 * Parse the given query `str`, returning an object.
 *
 * @param {String} str
 * @return {Object}
 * @api public
 */
const parse = str => {
  if (str === null || str === '') {
    return {};
  }

  const promote = (parent, key) => {
    if (parent[key].length === 0) {
      parent[key] = {};

      return parent[key];
    }

    const temp = {};

    for (const i in parent[key]) {
      if (parent[key].hasOwnProperty(i)) {
        temp[i] = parent[key][i];
      }
    }

    parent[key] = temp;

    return temp;
  };

  return String(str)
    .split('&')
    .reduce((ret, pair) => {
      try {
        pair = decodeURIComponent(pair.replace(/\+/g, ' '));
      } catch (er) {
        // ignore
      }

      const eql = pair.indexOf('=');

      // eslint-disable-next-line no-use-before-define
      const brace = lastBraceInKey(pair);
      let key = pair.substr(0, brace || eql);
      const parent = ret;
      let val = pair.substr(brace || eql, pair.length);

      val = val.substr(val.indexOf('=') + 1, val.length);

      // ?foo
      if (key === '') {
        key = pair;
        val = '';
      }

      // nested
      if (key.indexOf(']') !== -1) {
        const parts = key.split('[');

        const parse2 = (parts_, partParent, partKey) => {
          let part = parts_.shift();

          // end
          if (!part) {
            if (Array.isArray(partParent[partKey])) {
              partParent[partKey].push(val);
            } else if (typeof partParent[partKey] === 'object') {
              partParent[partKey] = val;
            } else if (typeof partParent[partKey] === 'undefined') {
              partParent[partKey] = val;
            } else {
              partParent[partKey] = [ partParent[partKey], val ];
            }

          // array
          } else {
            let obj = partParent[partKey] = partParent[partKey] || [];

            if (part === ']') {
              if (Array.isArray(obj)) {
                if (val !== '') {
                  obj.push(val);
                }
              } else if (typeof obj === 'object') {
                obj[Object.keys(obj).length] = val;
              } else {
                obj = partParent[partKey] = [ partParent[partKey], val ];
              }

            // prop
            } else if (part.indexOf(']') !== -1) {
              part = part.substr(0, part.length - 1);
              if (notint.test(part) && Array.isArray(obj)) {
                obj = promote(partParent, partKey);
              }

              parse(parts_, obj, part);

            // key
            } else {
              if (notint.test(part) && Array.isArray(obj)) {
                obj = promote(partParent, partKey);
              }

              parse(parts_, obj, part);
            }
          }
        };

        parse2(parts, parent, 'base');

      // optimize
      } else {
        if (notint.test(key) && Array.isArray(parent.base)) {
          const temp = {};

          for (const baseKey in parent.base) {
            if (parent.base.hasOwnProperty(baseKey)) {
              temp[baseKey] = parent.base[baseKey];
            }
          }

          parent.base = temp;
        }

        // eslint-disable-next-line no-use-before-define
        set(parent.base, key, val);
      }

      return ret;
    }, { base: {}}).base;
};

/**
 * Turn the given `obj` into a query string
 *
 * @param {Object} obj
 * @return {String}
 * @api public
 */

const stringify = (obj, prefix) => {
  if (Array.isArray(obj)) {
    // eslint-disable-next-line no-use-before-define
    return stringifyArray(obj, prefix);
  } else if (toString.call(obj) === '[object Object]') { // eslint-disable-line prefer-reflect
    // eslint-disable-next-line no-use-before-define
    return stringifyObject(obj, prefix);
  } else if (typeof obj === 'string') {
    // eslint-disable-next-line no-use-before-define
    return stringifyString(obj, prefix);
  }

  return prefix;
};

/**
 * Stringify the given `str`.
 *
 * @param {String} str
 * @param {String} prefix
 * @return {String}
 * @api private
 */

const stringifyString = (str, prefix) => {
  if (!prefix) {
    throw new TypeError('stringify expects an object');
  }

  return `${prefix}=${encodeURIComponent(str)}`;
};

/**
 * Stringify the given `arr`.
 *
 * @param {Array} arr
 * @param {String} prefix
 * @return {String}
 * @api private
 */

const stringifyArray = (arr, prefix) => {
  if (!prefix) {
    throw new TypeError('stringify expects an object');
  }

  const ret = [];

  for (let i = 0; i < arr.length; i++) {
    ret.push(stringify(arr[i], `${prefix}[]`));
  }

  return ret.join('&');
};

/**
 * Stringify the given `obj`.
 *
 * @param {Object} obj
 * @param {String} prefix
 * @return {String}
 * @api private
 */

const stringifyObject = (obj, prefix) => {
  const ret = [];
  const keys = Object.keys(obj);

  for (let i = 0; i < keys.length; ++i) {
    const key = keys[i];

    ret.push(stringify(obj[key], prefix ? `${prefix}[${encodeURIComponent(key)}]` : encodeURIComponent(key)));
  }

  return ret.join('&');
};

/**
 * Set `obj`'s `key` to `val` respecting
 * the weird and wonderful syntax of a qs,
 * where "foo=bar&foo=baz" becomes an array.
 *
 * @param {Object} obj
 * @param {String} key
 * @param {String} val
 * @api private
 */

const set = (obj, key, val) => {
  const value = obj[key];

  if (undefined === value) {
    obj[key] = val;
  } else if (Array.isArray(value)) {
    value.push(val);
  } else {
    obj[key] = [ value, val ];
  }
};

/**
 * Locate last brace in `str` within the key.
 *
 * @param {String} str
 * @return {Number}
 * @api private
 */

const lastBraceInKey = str => {
  let brace;

  for (let i = 0; i < str.length; ++i) {
    const character = str[i];

    if (character === ']') {
      brace = false;
    }

    if (character === '[') {
      brace = true;
    }

    if (character === '=' && !brace) {
      return i;
    }
  }
};

export {
  version,
  parse,
  stringify
};
