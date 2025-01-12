# Pirsch Analytics Plugin for Cloudflare Pages

A Cloudflare Pages plugin that automatically handles Pirsch Analytics tracking without injecting a script into your pages. This plugin tracks page views server-side, making it immune to ad blockers and providing more accurate analytics.

## Installation

```bash
npm install @solaasan/pirsch-analytics-cloudflare-pages
```

## Usage

1. First, create a client in your Pirsch dashboard:

   - Go to Settings > Integration
   - Click "Add Client"
   - Select "Client ID/Secret"
   - Save your client ID and secret

2. Create a KV namespace for hit batching:

   ```bash
   # Using wrangler CLI
   npx wrangler kv:namespace create PIRSCH_KV
   ```

   Or through the Cloudflare Dashboard:

   - Go to Workers & Pages
   - Click on "KV"
   - Create a new namespace called "PIRSCH_KV"
   - Copy the namespace ID

   Then add it to your `wrangler.toml`:

   ```toml
   [[kv_namespaces]]
   binding = "PIRSCH_KV"
   id = "your_namespace_id_here"
   ```

3. Configure your Cloudflare Pages project:

   - Go to your project settings
   - Under "Functions", add the following environment variables:
     ```
     pirschClientId=your_client_id_here
     pirschClientSecret=your_client_secret_here
     ```

4. Add the plugin to your project configuration:

   ```js
   // wrangler.toml
   [[plugins]];
   package = "@solaasan/pirsch-analytics-cloudflare-pages";
   ```

   Or if using Next.js:

   ```js
   // next.config.js
   module.exports = {
     cloudflare: {
       plugins: ["@solaasan/pirsch-analytics-cloudflare-pages"],
     },
   };
   ```

## Features

- Server-side tracking (no client-side JavaScript needed)
- Immune to ad blockers
- Efficient hit batching to reduce API calls
- Tracks all important visitor data:
  - Page views
  - Referrers
  - User agents
  - Client hints
  - Geographic information (via Cloudflare headers)
- Automatic token management
- Caches authentication tokens for better performance
- Only tracks HTML pages (ignores assets, APIs, etc.)

## Development

For local development, create a `.dev.vars` file with your credentials:

```env
pirschClientId=your_client_id_here
pirschClientSecret=your_client_secret_here
```

The plugin uses in-memory storage for hit batching during local development, so no KV setup is required for testing.

## License

MIT
