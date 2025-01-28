# KAPS Documentation

[![Built with Starlight](https://astro.badg.es/v2/built-with-starlight/tiny.svg)](https://starlight.astro.build)

Documentation site for KAPS - A secure file encryption tool. Built with Astro and Starlight.

## 🚀 Quick Start

```bash
# Install dependencies
pnpm install

# Start development server
pnpm run dev

# Build for production
pnpm run build
```

## 📚 Documentation Structure

```
.
├── public/              # Static assets
├── src/
│   ├── assets/         # Images and other assets
│   ├── content/
│   │   ├── docs/       # English documentation
│   │   └── docs/es/    # Spanish documentation
│   └── content.config.ts
└── astro.config.mjs    # Starlight configuration
```

## 🌍 Internationalization

- English (default): `/docs/`
- Spanish: `/docs/es/`

## 🛠️ Development

1. Clone the repository
2. Install dependencies: `pnpm install`
3. Start dev server: `pnpm run dev`
4. Visit `http://localhost:4321/kaps/`

## 🚀 Deployment

The documentation is automatically deployed to GitHub Pages via GitHub Actions when changes are pushed to the main branch.

## 📝 Contributing

1. Fork the repository
2. Create your feature branch
3. Make your changes
4. Submit a pull request

## 📄 License

MIT License - see LICENSE file for details.
