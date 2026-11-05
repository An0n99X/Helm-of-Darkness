# Helm of Darkness

Helm of Darkness is Anubhav Dash's security research site. The writing focuses on vulnerabilities in blockchain nodes and virtual-machine hosts: how an issue is reached, what the reproducer proves, what it costs a node, and how it was reported or fixed.

**Website:** <https://anubhavdash.github.io/Helm-of-Darkness/>

## Research

The [research archive](https://anubhavdash.github.io/Helm-of-Darkness/research/) contains five long-form reports and a seven-family index of 19 published Klever Go advisories that credit Anubhav Dash as a Finder or Reporter. Each advisory links to its GitHub Security Advisory for the authoritative severity, affected versions, patch, and credit record.

The articles are grouped by the failure pattern they investigate:

- [*The Bill Comes After the Body*](https://anubhavdash.github.io/Helm-of-Darkness/research/the-bill-comes-after-the-body/) — gas metering, managed-buffer copies, and bigint state snapshots.
- [*The Bigger the Theft, the Smaller the Number*](https://anubhavdash.github.io/Helm-of-Darkness/research/the-addition-overflowed-before-the-bounds-check/) — three managed-buffer range overflows and a staking supply-cap overflow.
- [*Smuggled Through the Storefront While the Border Guards Slept*](https://anubhavdash.github.io/Helm-of-Darkness/research/the-rule-was-set-the-operation-still-went-through/) — transfer restrictions and asset-change stop controls across marketplace, ITO, staking, royalties, and metadata.
- [*Death by Decimals: Bleeding a Chain One Fraction at a Time*](https://anubhavdash.github.io/Helm-of-Darkness/research/overflow-rounding-and-a-cap-that-stopped-being-a-cap/) — validator fee allocation and missed-slot arithmetic.
- [*The Silent Siege: A Thousand Open Doors, Nobody Knocking*](https://anubhavdash.github.io/Helm-of-Darkness/research/the-work-that-outlives-the-request/) — peer streams, managed-vector clone amplification, nested VM output growth, and startup-time node state.

The featured gas-metering article examines four findings in detail. These are its primary GHSA records; a related managed-vector advisory is also indexed on the research archive:

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
