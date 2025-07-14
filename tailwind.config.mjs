/** @type {import('tailwindcss').Config} */
export default {
	content: ['./src/**/*.{astro,html,js,jsx,md,mdx,svelte,ts,tsx,vue}'],
	darkMode: 'class',
	theme: {
		extend: {
			colors: {
				primary: {
					100: 'rgba(42, 133, 198, 0.1)',
					600: '#2A85C6',
					700: '#1e73a8',
					800: '#164f7a',
				}
			}
		},
	},
	plugins: [],
} 