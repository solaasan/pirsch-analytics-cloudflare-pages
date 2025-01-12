import type { PirschPluginArgs } from "../index";

interface TokenResponse {
  access_token: string;
  expires_at: string;
}

interface PirschHitPayload {
  url: string;
  ip: string;
  user_agent: string;
  accept_language: string | null;
  sec_ch_ua: string | null;
  sec_ch_ua_mobile: string | null;
  sec_ch_ua_platform: string | null;
  sec_ch_ua_platform_version: string | null;
  sec_ch_width: string | null;
  sec_ch_viewport_width: string | null;
  referrer: string | null;
}

let cachedToken: string | null = null;
let tokenExpiresAt: Date | null = null;

const MAX_RETRIES = 3;
const TIMEOUT_MS = 5000;
const TOKEN_RATE_LIMIT_WINDOW = 60000; // 1 minute
let tokenRequestCount = 0;
let lastTokenRequest = Date.now();

// Add rate limiting constants for hits
const HIT_RATE_LIMIT_WINDOW = 60000; // 1 minute
const MAX_HITS_PER_WINDOW = 100;
let hitRequestCount = 0;
let lastHitRequest = Date.now();

async function getAccessToken(
  clientId: string,
  clientSecret: string
): Promise<string> {
  // Rate limiting for token requests
  const now = Date.now();
  if (now - lastTokenRequest < TOKEN_RATE_LIMIT_WINDOW) {
    tokenRequestCount++;
    if (tokenRequestCount > 5) {
      // Max 5 requests per minute
      throw new Error("Token request rate limit exceeded");
    }
  } else {
    tokenRequestCount = 1;
    lastTokenRequest = now;
  }

  // Check if we have a valid cached token
  if (cachedToken && tokenExpiresAt && tokenExpiresAt > new Date()) {
    return cachedToken;
  }

  let lastError: Error | null = null;
  for (let i = 0; i < MAX_RETRIES; i++) {
    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS);

      const response = await fetch("https://api.pirsch.io/api/v1/token", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
        body: JSON.stringify({
          client_id: clientId,
          client_secret: clientSecret,
        }),
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (!response.ok) {
        throw new Error(`Failed to get access token: ${await response.text()}`);
      }

      const data: TokenResponse = await response.json();
      cachedToken = data.access_token;
      tokenExpiresAt = new Date(data.expires_at);

      return data.access_token;
    } catch (err) {
      lastError = err instanceof Error ? err : new Error(String(err));
      if (lastError.name === "AbortError") {
        console.error("Token request timeout");
      }
      // Wait before retry, with exponential backoff
      if (i < MAX_RETRIES - 1) {
        await new Promise((resolve) =>
          setTimeout(resolve, Math.pow(2, i) * 1000)
        );
      }
    }
  }

  throw lastError || new Error("Failed to get access token after retries");
}

// Add request validation
function validateHitPayload(payload: PirschHitPayload): boolean {
  try {
    // Validate URL
    new URL(payload.url);

    // Validate IP format (basic check)
    if (
      !/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(payload.ip) &&
      payload.ip !== "0.0.0.0"
    ) {
      return false;
    }

    // Ensure required fields are present
    if (!payload.url || !payload.ip || !payload.user_agent) {
      return false;
    }

    return true;
  } catch {
    return false;
  }
}

// Cache implementation using Cloudflare's Cache API
async function getCachedHit(cacheKey: string): Promise<Response | null> {
  try {
    const cache = caches.default;
    const response = await cache.match(cacheKey);
    return response || null;
  } catch {
    return null;
  }
}

async function cacheHit(cacheKey: string, response: Response): Promise<void> {
  try {
    const cache = caches.default;
    await cache.put(cacheKey, response.clone());
  } catch (error) {
    console.error("Cache error:", error);
  }
}

export const onRequest: PagesFunction<unknown, any, PirschPluginArgs> = async (
  context
) => {
  // Cast env to unknown first to satisfy TypeScript
  const env = context.env as unknown as PirschPluginArgs;
  if (!("pirschClientId" in env) || !("pirschClientSecret" in env)) {
    console.error("Missing required Pirsch credentials in environment");
    return await context.next();
  }

  const { pirschClientId, pirschClientSecret } = env;
  const request = context.request;

  // Validate required environment variables
  if (!pirschClientId || !pirschClientSecret) {
    console.error("Missing required Pirsch credentials");
    return await context.next();
  }

  const isDev =
    request.url.includes("localhost") || request.url.includes("127.0.0.1");

  // Sanitize URL for tracking
  const url = new URL(request.url);
  url.search = ""; // Remove query parameters for privacy
  const sanitizedUrl = url.toString();

  // Get the response first
  const response = await context.next();

  // For 304 responses, we know it's HTML if the request path doesn't have a file extension
  // or ends with .html
  const urlPath = url.pathname.split("/").pop();
  const isHtmlPath = !urlPath?.includes(".") || urlPath.endsWith(".html");
  const contentType = response.headers.get("content-type");
  const isHtmlResponse = contentType
    ? contentType.includes("text/html")
    : isHtmlPath;

  if (!isHtmlResponse) {
    return response;
  }

  try {
    // Apply hit rate limiting
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

    // Get a valid access token
    const accessToken = await getAccessToken(
      pirschClientId,
      pirschClientSecret
    );
    const authHeader = `Bearer ${accessToken}`;

    // Track the page view
    const headers = new Headers({
      Authorization: authHeader,
      "Content-Type": "application/json",
    });

    const payload: PirschHitPayload = {
      url: sanitizedUrl,
      ip:
        request.headers.get("cf-connecting-ip") ||
        request.headers.get("x-forwarded-for") ||
        "0.0.0.0",
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
      referrer: request.headers.get("referer"),
    };

    // Validate payload
    if (!validateHitPayload(payload)) {
      console.error("Invalid hit payload");
      return response;
    }

    // Check cache before sending hit
    const cacheKey = `pirsch-hit:${payload.url}:${payload.ip}:${Math.floor(
      Date.now() / 300000
    )}`; // 5-minute window
    const cachedResponse = await getCachedHit(cacheKey);
    if (cachedResponse) {
      if (isDev) console.log("Using cached hit response");
      return response;
    }

    // Send tracking data to Pirsch with timeout
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS);

    const trackingResponse = await fetch("https://api.pirsch.io/api/v1/hit", {
      method: "POST",
      headers,
      body: JSON.stringify(payload),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!trackingResponse.ok) {
      const errorText = await trackingResponse.text();
      console.error("Pirsch tracking failed:", errorText);
    } else {
      // Cache successful hit
      await cacheHit(cacheKey, trackingResponse);
      if (isDev) {
        console.log("Pirsch tracking successful!");
      }
    }
  } catch (error) {
    console.error(
      "Pirsch tracking error:",
      error instanceof Error ? error.message : String(error)
    );
  }

  return response;
};
