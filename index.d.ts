/// <reference types="@cloudflare/workers-types" />

export interface PirschPluginArgs extends Record<string, unknown> {
  websiteId: string;
  apiToken: string;
  domain?: string;
}

export default function (
  args: PirschPluginArgs
): PagesFunction<unknown, any, PirschPluginArgs>;
