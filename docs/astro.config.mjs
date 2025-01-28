import starlight from "@astrojs/starlight";
// @ts-check
import { defineConfig, passthroughImageService } from "astro/config";

// https://astro.build/config
export default defineConfig({
	// Add site configuration for GitHub Pages
	site: "https://stescobedo92.github.io",
	base: "kaps",
	image: {
		service: passthroughImageService(),
	},
	integrations: [
		starlight({
			title: "KAPS",
			defaultLocale: "root",
			locales: {
				root: {
					label: "English",
					lang: "en",
				},
				// Spanish docs in `src/content/docs/es/`
				es: {
					label: "Español",
				},
			},
			social: {
				github: "https://github.com/stescobedo92/kaps",
			},
			sidebar: [
				{
					label: "Guides",
					translations: {
						es: "Guías",
					},
					items: [
						// Each item here is one entry in the navigation menu.
						{
							label: "Installation Guide",
							translations: {
								es: "Guía de Instalación",
							},
							slug: "guides/installation",
						},
						{
							label: "Features Guide",
							translations: {
								es: "Guía de Características",
							},
							slug: "guides/features",
						},
						{
							label: "Usage Guide",
							translations: {
								es: "Guía de Uso",
							},
							slug: "guides/usage",
						},
					],
				},
			],
		}),
	],
});
