# Helm of Darkness

Helm of Darkness is Anubhav Dash's security research site. It publishes technical writeups on software vulnerabilities, with an emphasis on blockchain nodes and virtual machines. Reports focus on how an issue can be reached, what the proof of concept demonstrates, its impact, and how it was fixed or disclosed.

**Website:** <https://anubhavdash.github.io/Helm-of-Darkness/>

## Site

The site is a static [Astro](https://astro.build/) project styled with Tailwind CSS and published to GitHub Pages. Posts are Markdown files in [`src/content/posts/`](src/content/posts/); Astro builds the homepage, research index, and article pages from their frontmatter.

Run the local development server:

```sh
npm ci
npm run dev
```

Build the site for production:

```sh
npm run build
```

## Writing a post

Create a Markdown file under `src/content/posts/` and include the required fields:

```yaml
---
title: A clear article title
description: A concise summary of the research
slug: a-clear-article-title
published: 2026-11-05
tags:
  - Go
  - Virtual machines
featured: false
---
```

`updated` and `findings` are optional. A finding includes its name, severity, score, advisory identifier, and advisory URL. See the current article for an example.

## Project layout

- `src/content/posts/` — research articles and their metadata
- `src/pages/` — homepage, research index, and article routes
- `src/layouts/` — shared page layout and metadata
- `src/styles/` — site styles and responsive layouts
- `public/` — static images and the favicon

The GitHub Pages deployment workflow is in [`.github/workflows/deploy.yml`](.github/workflows/deploy.yml). It builds and publishes the site from `main`.

## Credits and licensing

Research articles and original artwork are © Anubhav Dash. Third-party code excerpts, project names, and advisory content remain the property of their respective owners and are linked to their sources.
