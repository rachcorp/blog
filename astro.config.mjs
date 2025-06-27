// @ts-check
import { defineConfig } from 'astro/config';
import mdx from '@astrojs/mdx';
import sitemap from '@astrojs/sitemap';
import tailwind from '@astrojs/tailwind';

// https://astro.build/config
export default defineConfig({
	site: 'https://cloudagent.io',
	base: '/blog',
	integrations: [mdx(), sitemap(), tailwind()],
	build: {
		format: 'directory',
		assets: '_astro'
	},
	output: 'static'
});
