# Helm of Darkness

An independent security research journal for long-form investigations into software behavior, failure, and repair.

**Website:** <https://anubhavdash.github.io/Helm-of-Darkness/>

## The site

The site is built with Astro and Tailwind CSS, then deployed to GitHub Pages with GitHub Actions. Articles are written in Markdown and live in [`src/content/posts/`](src/content/posts/).

To preview it locally:

```sh
npm ci
npm run dev
```

To create a post, add a Markdown file under `src/content/posts/` with the fields shown in an existing post. Astro uses that metadata to build the article page and research index automatically.

```yaml
---
title: A clear article title
description: A short summary for the homepage and search results.
slug: a-clear-article-title
published: 2026-11-05
tags:
  - Go
  - Virtual machines
featured: false
---
```

In the repository settings, set **Pages → Build and deployment → Source** to **GitHub Actions**. After that, pushes to `main` build and publish the site with [`.github/workflows/deploy.yml`](.github/workflows/deploy.yml).

## Repository map

- `src/content/posts/` — articles and their metadata
- `src/pages/` — homepage, research archive, and generated article routes
- `src/layouts/` — shared site and article layouts
- `src/styles/` — global typography and article styling
- `public/images/` — static images used by the site

## License

Article text and original artwork are © Anubhav Dash. Source excerpts remain subject to the license of their original projects.
