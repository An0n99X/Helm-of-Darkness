# Helm of Darkness

Helm of Darkness is Anubhav Dash's security research portfolio. It presents published advisories and upstream fixes in a searchable, filterable index with links to their source records.

**Website:** <https://anubhavdash.github.io/Helm-of-Darkness/>

The site is a static Astro project styled with Tailwind CSS. Its public index covers 19 Klever Go GHSAs, three merged FFmpeg fixes, and four additional accepted Klever Go fixes without separate advisories.

## Run locally

```sh
npm ci
npm run dev
```

Build the site with:

```sh
npm run build
```

The GitHub Pages workflow builds and publishes the site when changes are pushed to `main`.

## Project layout

- `src/pages/` — advisory portfolio and not-found page
- `src/data/disclosures.ts` — curated disclosure records and source links
- `src/layouts/` — shared page layout and metadata
- `src/styles/` — site typography and responsive layout
- `public/` — images and favicon

## Credits

Original artwork is © Anubhav Dash. Third-party code and project material remain attributed to their respective owners.
