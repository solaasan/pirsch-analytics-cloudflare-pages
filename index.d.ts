/// <reference types="@cloudflare/workers-types" />

export interface PirschPluginArgs extends Record<string, unknown> {
  pirschClientId: string;
  pirschClientSecret: string;
}

export default function (
  args: PirschPluginArgs
): PagesFunction<unknown, any, PirschPluginArgs>;
