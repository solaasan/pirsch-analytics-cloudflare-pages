var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// _middleware.ts
var cachedToken = null;
var tokenExpiresAt = null;
var MAX_RETRIES = 3;
var TIMEOUT_MS = 5e3;
var TOKEN_RATE_LIMIT_WINDOW = 6e4;
var tokenRequestCount = 0;
var lastTokenRequest = Date.now();
var HIT_RATE_LIMIT_WINDOW = 6e4;
var MAX_HITS_PER_WINDOW = 100;
var hitRequestCount = 0;
var lastHitRequest = Date.now();
var BATCH_SIZE = 3;
var BATCH_WINDOW_MS = 5e3;
var DEV_STORAGE = /* @__PURE__ */ new Map();
async function getAccessToken(clientId, clientSecret) {
  if (cachedToken && tokenExpiresAt && tokenExpiresAt > new Date(Date.now() + 3e5)) {
    return cachedToken;
  }
  const now = Date.now();
  if (now - lastTokenRequest < TOKEN_RATE_LIMIT_WINDOW) {
    tokenRequestCount++;
    if (tokenRequestCount > 5) {
      if (cachedToken && tokenExpiresAt && tokenExpiresAt > /* @__PURE__ */ new Date()) {
        console.warn("Using existing token due to rate limit");
        return cachedToken;
      }
      throw new Error("Token request rate limit exceeded");
    }
  } else {
    tokenRequestCount = 1;
    lastTokenRequest = now;
  }
  let lastError = null;
  for (let i = 0; i < MAX_RETRIES; i++) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS);
      const response = await fetch("https://api.pirsch.io/api/v1/token", {
        method: "POST",
        headers: {
          "Content-Type": "application/json"
        },
        body: JSON.stringify({
          client_id: clientId,
          client_secret: clientSecret
        }),
        signal: controller.signal
      });
      clearTimeout(timeoutId);
      if (!response.ok) {
        throw new Error(`Failed to get access token: ${await response.text()}`);
      }
      const data = await response.json();
      cachedToken = data.access_token;
      tokenExpiresAt = new Date(data.expires_at);
      return data.access_token;
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err));
      if (lastError.name === "AbortError") {
        console.error("Token request timeout");
      }
      if (i < MAX_RETRIES - 1) {
        await new Promise(
          (resolve) => setTimeout(resolve, Math.pow(2, i) * 1e3)
        );
      }
    }
  }
  if (cachedToken && tokenExpiresAt && tokenExpiresAt > /* @__PURE__ */ new Date()) {
    console.warn("Using existing token after request failure");
    return cachedToken;
  }
  throw lastError || new Error("Failed to get access token after retries");
}
__name(getAccessToken, "getAccessToken");
function validateHitPayload(payload) {
  try {
    new URL(payload.url);
    if (payload.ip !== "0.0.0.0") {
      const ipv4Regex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
      const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^([0-9a-fA-F]{1,4}:){1,7}:|^[0-9a-fA-F]{1,4}::$/;
      if (!ipv4Regex.test(payload.ip) && !ipv6Regex.test(payload.ip) && !payload.ip.includes(":")) {
        console.error("Invalid IP format:", payload.ip);
        return false;
      }
    }
    if (!payload.url?.trim() || !payload.ip?.trim() || !payload.user_agent?.trim()) {
      console.error("Missing required fields");
      return false;
    }
    return true;
  } catch (error) {
    console.error("Validation error:", error);
    return false;
  }
}
__name(validateHitPayload, "validateHitPayload");
async function getCachedHit(cacheKey) {
  try {
    const cache = caches.default;
    const response = await cache.match(
      `https://${new URL(cacheKey).hostname}/__pirsch/${encodeURIComponent(
        cacheKey
      )}`
    );
    return response || null;
  } catch {
    return null;
  }
}
__name(getCachedHit, "getCachedHit");
async function cacheHit(cacheKey, response) {
  try {
    const cache = caches.default;
    const cacheResponse = new Response(response.clone().body, {
      ...response,
      headers: {
        ...response.headers,
        "Cache-Control": "public, max-age=300"
        // 5 minutes
      }
    });
    await cache.put(
      `https://${new URL(cacheKey).hostname}/__pirsch/${encodeURIComponent(
        cacheKey
      )}`,
      cacheResponse
    );
  } catch (error) {
    console.error("Cache error:", error);
  }
}
__name(cacheHit, "cacheHit");
async function getBatchedHits(cacheKey, env) {
  try {
    if (cacheKey.includes("localhost") || cacheKey.includes("127.0.0.1")) {
      return DEV_STORAGE.get(cacheKey) || null;
    }
    const kv = env["PIRSCH_KV"];
    const data = await kv.get(cacheKey, "json");
    return data;
  } catch {
    return null;
  }
}
__name(getBatchedHits, "getBatchedHits");
async function storeBatchedHits(cacheKey, batch, env) {
  try {
    if (cacheKey.includes("localhost") || cacheKey.includes("127.0.0.1")) {
      DEV_STORAGE.set(cacheKey, batch);
      return;
    }
    const kv = env["PIRSCH_KV"];
    await kv.put(cacheKey, JSON.stringify(batch), {
      expirationTtl: 60 * 60
      // 1 hour expiration
    });
  } catch (error) {
    console.error("Batch storage error:", error);
  }
}
__name(storeBatchedHits, "storeBatchedHits");
async function sendBatchedHits(hits, authHeader) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS);
  try {
    console.log(`Sending batch of ${hits.length} hits to Pirsch...`);
    const response = await fetch("https://api.pirsch.io/api/v1/hit/batch", {
      method: "POST",
      headers: {
        Authorization: authHeader,
        "Content-Type": "application/json"
      },
      body: JSON.stringify(hits),
      signal: controller.signal
    });
    clearTimeout(timeoutId);
    if (!response.ok) {
      const errorText = await response.text();
      throw new Error(
        `Failed to send batch: ${response.status} - ${errorText}`
      );
    }
    console.log("Batch sent successfully!");
  } catch (error) {
    console.error("Failed to send batched hits:", error);
  }
}
__name(sendBatchedHits, "sendBatchedHits");
var onRequest = /* @__PURE__ */ __name(async (context) => {
  const env = context.env;
  if (!("pirschClientId" in env) || !("pirschClientSecret" in env)) {
    console.error("Missing required Pirsch credentials in environment");
    return await context.next();
  }
  const { pirschClientId, pirschClientSecret } = env;
  const request = context.request;
  if (!pirschClientId || !pirschClientSecret) {
    console.error("Missing required Pirsch credentials");
    return await context.next();
  }
  const isDev = request.url.includes("localhost") || request.url.includes("127.0.0.1");
  const url = new URL(request.url);
  url.search = "";
  const sanitizedUrl = url.toString();
  const response = await context.next();
  const urlPath = url.pathname.split("/").pop();
  const isHtmlPath = !urlPath?.includes(".") || urlPath.endsWith(".html");
  const contentType = response.headers.get("content-type");
  const isHtmlResponse = contentType ? contentType.includes("text/html") : isHtmlPath;
  if (!isHtmlResponse) {
    return response;
  }
  try {
    const now = Date.now();
    if (now - lastHitRequest < HIT_RATE_LIMIT_WINDOW) {
      hitRequestCount++;
      if (hitRequestCount > MAX_HITS_PER_WINDOW) {
        console.warn("Hit rate limit exceeded");
        return response;
      }
    } else {
      hitRequestCount = 1;
      lastHitRequest = now;
    }
    const accessToken = await getAccessToken(
      pirschClientId,
      pirschClientSecret
    );
    const authHeader = `Bearer ${accessToken}`;
    const headers = new Headers({
      Authorization: authHeader,
      "Content-Type": "application/json"
    });
    const payload = {
      url: sanitizedUrl,
      ip: request.headers.get("cf-connecting-ip") || request.headers.get("x-forwarded-for") || "0.0.0.0",
      user_agent: request.headers.get("user-agent") || "",
      accept_language: request.headers.get("accept-language"),
      sec_ch_ua: request.headers.get("sec-ch-ua"),
      sec_ch_ua_mobile: request.headers.get("sec-ch-ua-mobile"),
      sec_ch_ua_platform: request.headers.get("sec-ch-ua-platform"),
      sec_ch_ua_platform_version: request.headers.get(
        "sec-ch-ua-platform-version"
      ),
      sec_ch_width: request.headers.get("sec-ch-width"),
      sec_ch_viewport_width: request.headers.get("sec-ch-viewport-width"),
      referrer: request.headers.get("referer")
    };
    if (!validateHitPayload(payload)) {
      console.error("Invalid hit payload");
      return response;
    }
    const hitCacheKey = `${request.url}/__pirsch/hit/${payload.ip}/${Math.floor(
      Date.now() / 3e5
    )}`;
    const cachedHit = await getCachedHit(hitCacheKey);
    if (cachedHit) {
      if (isDev)
        console.log("Using cached hit response");
      return response;
    }
    const BATCH_KEY = "current-batch";
    let batch = await getBatchedHits(BATCH_KEY, env);
    if (!batch) {
      batch = { hits: [], lastUpdate: Date.now() };
      if (isDev)
        console.log("Creating new batch");
    } else if (isDev) {
      console.log(
        `Found existing batch with ${batch.hits.length} hits (last update: ${Date.now() - batch.lastUpdate}ms ago)`
      );
    }
    const timeSinceLastUpdate = Date.now() - batch.lastUpdate;
    if (timeSinceLastUpdate >= BATCH_WINDOW_MS && batch.hits.length > 0) {
      if (isDev) {
        console.log(
          `Time window reached (${timeSinceLastUpdate}ms), sending batch of ${batch.hits.length} hits...`
        );
      }
      await sendBatchedHits(batch.hits, authHeader);
      batch = { hits: [], lastUpdate: Date.now() };
    }
    batch.hits.push(payload);
    if (batch.hits.length === 1) {
      batch.lastUpdate = Date.now();
    }
    if (batch.hits.length >= BATCH_SIZE) {
      if (isDev) {
        console.log(
          `Batch size reached: ${batch.hits.length}/${BATCH_SIZE} hits`
        );
      }
      await sendBatchedHits(batch.hits, authHeader);
      batch = { hits: [], lastUpdate: Date.now() };
    } else if (isDev) {
      console.log(`Waiting for more hits:
        - Current batch size: ${batch.hits.length}/${BATCH_SIZE}
        - Time since first hit: ${Date.now() - batch.lastUpdate}ms/${BATCH_WINDOW_MS}ms`);
    }
    await storeBatchedHits(BATCH_KEY, batch, env);
    const trackingResponse = new Response(JSON.stringify({ status: "queued" }));
    await cacheHit(hitCacheKey, trackingResponse);
    if (isDev) {
      console.log(
        `Hit ${batch.hits.length === 1 ? "queued" : "added to batch"} (${batch.hits.length} hits in current batch)`
      );
    }
  } catch (error) {
    console.error(
      "Pirsch tracking error:",
      error instanceof Error ? error.message : String(error)
    );
  }
  return response;
}, "onRequest");

// ../.wrangler/tmp/pages-6zTXlW/functionsRoutes-0.1377548842673051.mjs
var routes = [
  {
    routePath: "/",
    mountPath: "/",
    method: "",
    middlewares: [onRequest],
    modules: []
  }
];

// ../node_modules/path-to-regexp/dist.es2015/index.js
function lexer(str) {
  var tokens = [];
  var i = 0;
  while (i < str.length) {
    var char = str[i];
    if (char === "*" || char === "+" || char === "?") {
      tokens.push({ type: "MODIFIER", index: i, value: str[i++] });
      continue;
    }
    if (char === "\\") {
      tokens.push({ type: "ESCAPED_CHAR", index: i++, value: str[i++] });
      continue;
    }
    if (char === "{") {
      tokens.push({ type: "OPEN", index: i, value: str[i++] });
      continue;
    }
    if (char === "}") {
      tokens.push({ type: "CLOSE", index: i, value: str[i++] });
      continue;
    }
    if (char === ":") {
      var name = "";
      var j = i + 1;
      while (j < str.length) {
        var code = str.charCodeAt(j);
        if (
          // `0-9`
          code >= 48 && code <= 57 || // `A-Z`
          code >= 65 && code <= 90 || // `a-z`
          code >= 97 && code <= 122 || // `_`
          code === 95
        ) {
          name += str[j++];
          continue;
        }
        break;
      }
      if (!name)
        throw new TypeError("Missing parameter name at ".concat(i));
      tokens.push({ type: "NAME", index: i, value: name });
      i = j;
      continue;
    }
    if (char === "(") {
      var count = 1;
      var pattern = "";
      var j = i + 1;
      if (str[j] === "?") {
        throw new TypeError('Pattern cannot start with "?" at '.concat(j));
      }
      while (j < str.length) {
        if (str[j] === "\\") {
          pattern += str[j++] + str[j++];
          continue;
        }
        if (str[j] === ")") {
          count--;
          if (count === 0) {
            j++;
            break;
          }
        } else if (str[j] === "(") {
          count++;
          if (str[j + 1] !== "?") {
            throw new TypeError("Capturing groups are not allowed at ".concat(j));
          }
        }
        pattern += str[j++];
      }
      if (count)
        throw new TypeError("Unbalanced pattern at ".concat(i));
      if (!pattern)
        throw new TypeError("Missing pattern at ".concat(i));
      tokens.push({ type: "PATTERN", index: i, value: pattern });
      i = j;
      continue;
    }
    tokens.push({ type: "CHAR", index: i, value: str[i++] });
  }
  tokens.push({ type: "END", index: i, value: "" });
  return tokens;
}
__name(lexer, "lexer");
function parse(str, options) {
  if (options === void 0) {
    options = {};
  }
  var tokens = lexer(str);
  var _a = options.prefixes, prefixes = _a === void 0 ? "./" : _a, _b = options.delimiter, delimiter = _b === void 0 ? "/#?" : _b;
  var result = [];
  var key = 0;
  var i = 0;
  var path = "";
  var tryConsume = /* @__PURE__ */ __name(function(type) {
    if (i < tokens.length && tokens[i].type === type)
      return tokens[i++].value;
  }, "tryConsume");
  var mustConsume = /* @__PURE__ */ __name(function(type) {
    var value2 = tryConsume(type);
    if (value2 !== void 0)
      return value2;
    var _a2 = tokens[i], nextType = _a2.type, index = _a2.index;
    throw new TypeError("Unexpected ".concat(nextType, " at ").concat(index, ", expected ").concat(type));
  }, "mustConsume");
  var consumeText = /* @__PURE__ */ __name(function() {
    var result2 = "";
    var value2;
    while (value2 = tryConsume("CHAR") || tryConsume("ESCAPED_CHAR")) {
      result2 += value2;
    }
    return result2;
  }, "consumeText");
  var isSafe = /* @__PURE__ */ __name(function(value2) {
    for (var _i = 0, delimiter_1 = delimiter; _i < delimiter_1.length; _i++) {
      var char2 = delimiter_1[_i];
      if (value2.indexOf(char2) > -1)
        return true;
    }
    return false;
  }, "isSafe");
  var safePattern = /* @__PURE__ */ __name(function(prefix2) {
    var prev = result[result.length - 1];
    var prevText = prefix2 || (prev && typeof prev === "string" ? prev : "");
    if (prev && !prevText) {
      throw new TypeError('Must have text between two parameters, missing text after "'.concat(prev.name, '"'));
    }
    if (!prevText || isSafe(prevText))
      return "[^".concat(escapeString(delimiter), "]+?");
    return "(?:(?!".concat(escapeString(prevText), ")[^").concat(escapeString(delimiter), "])+?");
  }, "safePattern");
  while (i < tokens.length) {
    var char = tryConsume("CHAR");
    var name = tryConsume("NAME");
    var pattern = tryConsume("PATTERN");
    if (name || pattern) {
      var prefix = char || "";
      if (prefixes.indexOf(prefix) === -1) {
        path += prefix;
        prefix = "";
      }
      if (path) {
        result.push(path);
        path = "";
      }
      result.push({
        name: name || key++,
        prefix,
        suffix: "",
        pattern: pattern || safePattern(prefix),
        modifier: tryConsume("MODIFIER") || ""
      });
      continue;
    }
    var value = char || tryConsume("ESCAPED_CHAR");
    if (value) {
      path += value;
      continue;
    }
    if (path) {
      result.push(path);
      path = "";
    }
    var open = tryConsume("OPEN");
    if (open) {
      var prefix = consumeText();
      var name_1 = tryConsume("NAME") || "";
      var pattern_1 = tryConsume("PATTERN") || "";
      var suffix = consumeText();
      mustConsume("CLOSE");
      result.push({
        name: name_1 || (pattern_1 ? key++ : ""),
        pattern: name_1 && !pattern_1 ? safePattern(prefix) : pattern_1,
        prefix,
        suffix,
        modifier: tryConsume("MODIFIER") || ""
      });
      continue;
    }
    mustConsume("END");
  }
  return result;
}
__name(parse, "parse");
function match(str, options) {
  var keys = [];
  var re = pathToRegexp(str, keys, options);
  return regexpToFunction(re, keys, options);
}
__name(match, "match");
function regexpToFunction(re, keys, options) {
  if (options === void 0) {
    options = {};
  }
  var _a = options.decode, decode = _a === void 0 ? function(x) {
    return x;
  } : _a;
  return function(pathname) {
    var m = re.exec(pathname);
    if (!m)
      return false;
    var path = m[0], index = m.index;
    var params = /* @__PURE__ */ Object.create(null);
    var _loop_1 = /* @__PURE__ */ __name(function(i2) {
      if (m[i2] === void 0)
        return "continue";
      var key = keys[i2 - 1];
      if (key.modifier === "*" || key.modifier === "+") {
        params[key.name] = m[i2].split(key.prefix + key.suffix).map(function(value) {
          return decode(value, key);
        });
      } else {
        params[key.name] = decode(m[i2], key);
      }
    }, "_loop_1");
    for (var i = 1; i < m.length; i++) {
      _loop_1(i);
    }
    return { path, index, params };
  };
}
__name(regexpToFunction, "regexpToFunction");
function escapeString(str) {
  return str.replace(/([.+*?=^!:${}()[\]|/\\])/g, "\\$1");
}
__name(escapeString, "escapeString");
function flags(options) {
  return options && options.sensitive ? "" : "i";
}
__name(flags, "flags");
function regexpToRegexp(path, keys) {
  if (!keys)
    return path;
  var groupsRegex = /\((?:\?<(.*?)>)?(?!\?)/g;
  var index = 0;
  var execResult = groupsRegex.exec(path.source);
  while (execResult) {
    keys.push({
      // Use parenthesized substring match if available, index otherwise
      name: execResult[1] || index++,
      prefix: "",
      suffix: "",
      modifier: "",
      pattern: ""
    });
    execResult = groupsRegex.exec(path.source);
  }
  return path;
}
__name(regexpToRegexp, "regexpToRegexp");
function arrayToRegexp(paths, keys, options) {
  var parts = paths.map(function(path) {
    return pathToRegexp(path, keys, options).source;
  });
  return new RegExp("(?:".concat(parts.join("|"), ")"), flags(options));
}
__name(arrayToRegexp, "arrayToRegexp");
function stringToRegexp(path, keys, options) {
  return tokensToRegexp(parse(path, options), keys, options);
}
__name(stringToRegexp, "stringToRegexp");
function tokensToRegexp(tokens, keys, options) {
  if (options === void 0) {
    options = {};
  }
  var _a = options.strict, strict = _a === void 0 ? false : _a, _b = options.start, start = _b === void 0 ? true : _b, _c = options.end, end = _c === void 0 ? true : _c, _d = options.encode, encode = _d === void 0 ? function(x) {
    return x;
  } : _d, _e = options.delimiter, delimiter = _e === void 0 ? "/#?" : _e, _f = options.endsWith, endsWith = _f === void 0 ? "" : _f;
  var endsWithRe = "[".concat(escapeString(endsWith), "]|$");
  var delimiterRe = "[".concat(escapeString(delimiter), "]");
  var route = start ? "^" : "";
  for (var _i = 0, tokens_1 = tokens; _i < tokens_1.length; _i++) {
    var token = tokens_1[_i];
    if (typeof token === "string") {
      route += escapeString(encode(token));
    } else {
      var prefix = escapeString(encode(token.prefix));
      var suffix = escapeString(encode(token.suffix));
      if (token.pattern) {
        if (keys)
          keys.push(token);
        if (prefix || suffix) {
          if (token.modifier === "+" || token.modifier === "*") {
            var mod = token.modifier === "*" ? "?" : "";
            route += "(?:".concat(prefix, "((?:").concat(token.pattern, ")(?:").concat(suffix).concat(prefix, "(?:").concat(token.pattern, "))*)").concat(suffix, ")").concat(mod);
          } else {
            route += "(?:".concat(prefix, "(").concat(token.pattern, ")").concat(suffix, ")").concat(token.modifier);
          }
        } else {
          if (token.modifier === "+" || token.modifier === "*") {
            throw new TypeError('Can not repeat "'.concat(token.name, '" without a prefix and suffix'));
          }
          route += "(".concat(token.pattern, ")").concat(token.modifier);
        }
      } else {
        route += "(?:".concat(prefix).concat(suffix, ")").concat(token.modifier);
      }
    }
  }
  if (end) {
    if (!strict)
      route += "".concat(delimiterRe, "?");
    route += !options.endsWith ? "$" : "(?=".concat(endsWithRe, ")");
  } else {
    var endToken = tokens[tokens.length - 1];
    var isEndDelimited = typeof endToken === "string" ? delimiterRe.indexOf(endToken[endToken.length - 1]) > -1 : endToken === void 0;
    if (!strict) {
      route += "(?:".concat(delimiterRe, "(?=").concat(endsWithRe, "))?");
    }
    if (!isEndDelimited) {
      route += "(?=".concat(delimiterRe, "|").concat(endsWithRe, ")");
    }
  }
  return new RegExp(route, flags(options));
}
__name(tokensToRegexp, "tokensToRegexp");
function pathToRegexp(path, keys, options) {
  if (path instanceof RegExp)
    return regexpToRegexp(path, keys);
  if (Array.isArray(path))
    return arrayToRegexp(path, keys, options);
  return stringToRegexp(path, keys, options);
}
__name(pathToRegexp, "pathToRegexp");

// ../node_modules/wrangler/templates/pages-template-plugin.ts
var escapeRegex = /[.+?^${}()|[\]\\]/g;
function* executeRequest(request, relativePathname) {
  for (const route of [...routes].reverse()) {
    if (route.method && route.method !== request.method) {
      continue;
    }
    const routeMatcher = match(route.routePath.replace(escapeRegex, "\\$&"), {
      end: false
    });
    const mountMatcher = match(route.mountPath.replace(escapeRegex, "\\$&"), {
      end: false
    });
    const matchResult = routeMatcher(relativePathname);
    const mountMatchResult = mountMatcher(relativePathname);
    if (matchResult && mountMatchResult) {
      for (const handler of route.middlewares.flat()) {
        yield {
          handler,
          params: matchResult.params,
          path: mountMatchResult.path
        };
      }
    }
  }
  for (const route of routes) {
    if (route.method && route.method !== request.method) {
      continue;
    }
    const routeMatcher = match(route.routePath.replace(escapeRegex, "\\$&"), {
      end: true
    });
    const mountMatcher = match(route.mountPath.replace(escapeRegex, "\\$&"), {
      end: false
    });
    const matchResult = routeMatcher(relativePathname);
    const mountMatchResult = mountMatcher(relativePathname);
    if (matchResult && mountMatchResult && route.modules.length) {
      for (const handler of route.modules.flat()) {
        yield {
          handler,
          params: matchResult.params,
          path: matchResult.path
        };
      }
      break;
    }
  }
}
__name(executeRequest, "executeRequest");
function pages_template_plugin_default(pluginArgs) {
  const onRequest2 = /* @__PURE__ */ __name(async (workerContext) => {
    let { request } = workerContext;
    const { env, next } = workerContext;
    let { data } = workerContext;
    const url = new URL(request.url);
    const relativePathname = `/${url.pathname.replace(workerContext.functionPath, "") || ""}`.replace(/^\/\//, "/");
    const handlerIterator = executeRequest(request, relativePathname);
    const pluginNext = /* @__PURE__ */ __name(async (input, init) => {
      if (input !== void 0) {
        let url2 = input;
        if (typeof input === "string") {
          url2 = new URL(input, request.url).toString();
        }
        request = new Request(url2, init);
      }
      const result = handlerIterator.next();
      if (result.done === false) {
        const { handler, params, path } = result.value;
        const context = {
          request: new Request(request.clone()),
          functionPath: workerContext.functionPath + path,
          next: pluginNext,
          params,
          get data() {
            return data;
          },
          set data(value) {
            if (typeof value !== "object" || value === null) {
              throw new Error("context.data must be an object");
            }
            data = value;
          },
          pluginArgs,
          env,
          waitUntil: workerContext.waitUntil.bind(workerContext),
          passThroughOnException: workerContext.passThroughOnException.bind(workerContext)
        };
        const response = await handler(context);
        return cloneResponse(response);
      } else {
        return next(request);
      }
    }, "pluginNext");
    return pluginNext();
  }, "onRequest");
  return onRequest2;
}
__name(pages_template_plugin_default, "default");
var cloneResponse = /* @__PURE__ */ __name((response) => (
  // https://fetch.spec.whatwg.org/#null-body-status
  new Response(
    [101, 204, 205, 304].includes(response.status) ? null : response.body,
    response
  )
), "cloneResponse");
export {
  pages_template_plugin_default as default
};
