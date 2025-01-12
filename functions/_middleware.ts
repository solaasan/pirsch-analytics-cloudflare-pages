import { Pirsch } from "pirsch-sdk";
import type { PirschPluginArgs } from "../index";

export const onRequest: PagesFunction<unknown, any, PirschPluginArgs> = async (
  context
) => {
  const env = context.env as unknown as PirschPluginArgs;
  const { websiteId, apiToken, domain } = env;
  const request = context.request;

  // Initialize Pirsch client
  const client = new Pirsch({
    hostname: domain || new URL(request.url).hostname,
    clientId: websiteId,
    clientSecret: apiToken,
  });

  try {
    // Track the page view
    await client.hit({
      url: request.url,
      ip:
        request.headers.get("cf-connecting-ip") ||
        request.headers.get("x-forwarded-for") ||
        "0.0.0.0",
      user_agent: request.headers.get("user-agent") || "",
      accept_language: request.headers.get("accept-language") || undefined,
      sec_ch_ua: request.headers.get("sec-ch-ua") || undefined,
      sec_ch_ua_mobile: request.headers.get("sec-ch-ua-mobile") || undefined,
      sec_ch_ua_platform:
        request.headers.get("sec-ch-ua-platform") || undefined,
      sec_ch_ua_platform_version:
        request.headers.get("sec-ch-ua-platform-version") || undefined,
      sec_ch_width: request.headers.get("sec-ch-width") || undefined,
      sec_ch_viewport_width:
        request.headers.get("sec-ch-viewport-width") || undefined,
      referrer: request.headers.get("referer") || undefined,
    });
  } catch (error) {
    // Log error but don't block the request
    console.error("Pirsch tracking error:", error);
  }

  // Continue with the request
  return await context.next();
};
