# Helm of Darkness

Helm of Darkness is Anubhav Dash's security research site. The writing focuses on vulnerabilities in blockchain nodes and virtual-machine hosts: how an issue is reached, what the reproducer proves, what it costs a node, and how it was reported or fixed.

**Website:** <https://anubhavdash.github.io/Helm-of-Darkness/>

## Featured research

[*The Bill Comes After the Body*](https://anubhavdash.github.io/Helm-of-Darkness/research/the-bill-comes-after-the-body/) examines four Klever Go VM findings where gas metering failed to bound host-side allocations, repeated copies, or state snapshots. The post includes test measurements and distinguishes the independent reports from findings credited to multiple researchers.

The four linked advisories are the source of record for severity, affected versions, disclosure details, and finder or reporter credit:

- [`MBufferSetRandom` — High](https://github.com/klever-io/klever-go/security/advisories/GHSA-cg9c-gcgh-qgc3)
- [`readKDATransfers` — High](https://github.com/klever-io/klever-go/security/advisories/GHSA-3xw3-gjh2-5j94)
- [`BigIntShl` — High](https://github.com/klever-io/klever-go/security/advisories/GHSA-r2gq-244g-h8p2)
- [`PushState` — Moderate](https://github.com/klever-io/klever-go/security/advisories/GHSA-gjm9-w2m6-rmp9)

## Run the site locally

The site is a static Astro project styled with Tailwind CSS. Posts are Markdown files in [`src/content/posts/`](src/content/posts/); Astro builds the home page, research index, and article pages from their frontmatter.

```sh
npm ci
npm run dev
```

Build the site with:

```sh
npm run build
```

## Add a post

Create a Markdown file under `src/content/posts/` with the required frontmatter:

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

`updated` and `findings` are optional. Each finding has a name, severity, score, advisory identifier, and advisory URL. See the current post for an example.

## Project layout

- `src/content/posts/` — research articles and their metadata
- `src/pages/` — home page, research index, and article routes
- `src/layouts/` — shared page layout and metadata
- `src/styles/` — site typography and responsive layouts
- `public/` — static images and the favicon

The [GitHub Pages workflow](.github/workflows/deploy.yml) builds and publishes the site when changes are pushed to `main`.

## Credits

Research articles and original artwork are © Anubhav Dash. Third-party code, advisories, and project material remain attributed to their respective owners and are linked to their sources.
