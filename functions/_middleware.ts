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

interface BatchedHits {
  hits: PirschHitPayload[];
  lastUpdate: number;
}

// Adjust batch settings based on environment
const BATCH_SIZE = 3; // Reduced from 10 for easier testing
const BATCH_WINDOW_MS = 5000; // Reduced from 10s to 5s for easier testing

// Development-only in-memory storage
const DEV_STORAGE = new Map<string, BatchedHits>();

async function getAccessToken(
  clientId: string,
  clientSecret: string
): Promise<string> {
  // Check if we have a valid cached token with 5 minute buffer
  if (
    cachedToken &&
    tokenExpiresAt &&
    tokenExpiresAt > new Date(Date.now() + 300000)
  ) {
    return cachedToken;
  }

  // Rate limiting for token requests
  const now = Date.now();
  if (now - lastTokenRequest < TOKEN_RATE_LIMIT_WINDOW) {
    tokenRequestCount++;
    if (tokenRequestCount > 5) {
      // If we hit the rate limit but have a token that's not completely expired, use it
      if (cachedToken && tokenExpiresAt && tokenExpiresAt > new Date()) {
        console.warn("Using existing token due to rate limit");
        return cachedToken;
      }
      throw new Error("Token request rate limit exceeded");
    }
  } else {
    tokenRequestCount = 1;
    lastTokenRequest = now;
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

  // If we have a cached token that's not completely expired, use it as fallback
  if (cachedToken && tokenExpiresAt && tokenExpiresAt > new Date()) {
    console.warn("Using existing token after request failure");
    return cachedToken;
  }

  throw lastError || new Error("Failed to get access token after retries");
}

// Add request validation
function validateHitPayload(payload: PirschHitPayload): boolean {
  try {
    // Validate URL
    new URL(payload.url);

    // Validate IP format - allow IPv4, IPv6, and special cases
    if (payload.ip !== "0.0.0.0") {
      // Basic IPv4 check
      const ipv4Regex = /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/;
      // Basic IPv6 check
      const ipv6Regex =
        /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^([0-9a-fA-F]{1,4}:){1,7}:|^[0-9a-fA-F]{1,4}::$/;
      // Check if it's a valid Cloudflare IPv4 or IPv6
      if (
        !ipv4Regex.test(payload.ip) &&
        !ipv6Regex.test(payload.ip) &&
        !payload.ip.includes(":")
      ) {
        console.error("Invalid IP format:", payload.ip);
        return false;
      }
    }

    // Ensure required fields are present and not empty strings
    if (
      !payload.url?.trim() ||
      !payload.ip?.trim() ||
      !payload.user_agent?.trim()
    ) {
      console.error("Missing required fields");
      return false;
    }

    return true;
  } catch (error) {
    console.error("Validation error:", error);
    return false;
  }
}

// Cache implementation using Cloudflare's Cache API
async function getCachedHit(cacheKey: string): Promise<Response | null> {
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

async function cacheHit(cacheKey: string, response: Response): Promise<void> {
  try {
    const cache = caches.default;
    const cacheResponse = new Response(response.clone().body, {
      ...response,
      headers: {
        ...response.headers,
        "Cache-Control": "public, max-age=300", // 5 minutes
      },
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

async function getBatchedHits(
  cacheKey: string,
  env: PirschPluginArgs
): Promise<BatchedHits | null> {
  try {
    if (cacheKey.includes("localhost") || cacheKey.includes("127.0.0.1")) {
      return DEV_STORAGE.get(cacheKey) || null;
    }
    const kv = env["PIRSCH_KV"] as KVNamespace;
    const data = await kv.get(cacheKey, "json");
    return data as BatchedHits | null;
  } catch {
    return null;
  }
}

async function storeBatchedHits(
  cacheKey: string,
  batch: BatchedHits,
  env: PirschPluginArgs
): Promise<void> {
  try {
    if (cacheKey.includes("localhost") || cacheKey.includes("127.0.0.1")) {
      DEV_STORAGE.set(cacheKey, batch);
      return;
    }
    const kv = env["PIRSCH_KV"] as KVNamespace;
    await kv.put(cacheKey, JSON.stringify(batch), {
      expirationTtl: 60 * 60, // 1 hour expiration
    });
  } catch (error) {
    console.error("Batch storage error:", error);
  }
}

async function sendBatchedHits(
  hits: PirschHitPayload[],
  authHeader: string
): Promise<void> {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), TIMEOUT_MS);

  try {
    console.log(`Sending batch of ${hits.length} hits to Pirsch...`);
    const response = await fetch("https://api.pirsch.io/api/v1/hit/batch", {
      method: "POST",
      headers: {
        Authorization: authHeader,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(hits),
      signal: controller.signal,
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
    // On failure, we'll just let the hits be processed again
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

    // Check individual hit cache to prevent duplicates
    const hitCacheKey = `${request.url}/__pirsch/hit/${payload.ip}/${Math.floor(
      Date.now() / 300000
    )}`; // 5-minute window
    const cachedHit = await getCachedHit(hitCacheKey);
    if (cachedHit) {
      if (isDev) console.log("Using cached hit response");
      return response;
    }

    // Try to add to batch
    const BATCH_KEY = "current-batch";
    let batch = await getBatchedHits(BATCH_KEY, env);

    if (!batch) {
      batch = { hits: [], lastUpdate: Date.now() };
      if (isDev) console.log("Creating new batch");
    } else if (isDev) {
      console.log(
        `Found existing batch with ${batch.hits.length} hits (last update: ${
          Date.now() - batch.lastUpdate
        }ms ago)`
      );
    }

    // Check if we should send the current batch due to time
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

    // Add the new hit to the batch
    batch.hits.push(payload);
    // Only update the lastUpdate time when creating a new batch
    if (batch.hits.length === 1) {
      batch.lastUpdate = Date.now();
    }

    // If we've reached batch size, send the batch
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
        - Time since first hit: ${
          Date.now() - batch.lastUpdate
        }ms/${BATCH_WINDOW_MS}ms`);
    }

    // Store updated batch
    await storeBatchedHits(BATCH_KEY, batch, env);

    // Cache the individual hit to prevent duplicates
    const trackingResponse = new Response(JSON.stringify({ status: "queued" }));
    await cacheHit(hitCacheKey, trackingResponse);

    if (isDev) {
      console.log(
        `Hit ${batch.hits.length === 1 ? "queued" : "added to batch"} (${
          batch.hits.length
        } hits in current batch)`
      );
    }
  } catch (error) {
    console.error(
      "Pirsch tracking error:",
      error instanceof Error ? error.message : String(error)
    );
  }

  return response;
};
