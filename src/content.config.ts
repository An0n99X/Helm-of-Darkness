import { defineCollection, z } from "astro:content";
import { glob } from "astro/loaders";

const posts = defineCollection({
  loader: glob({ pattern: "**/*.md", base: "./src/content/posts" }),
  schema: z.object({
    title: z.string(),
    description: z.string(),
    slug: z.string(),
    published: z.coerce.date(),
    updated: z.coerce.date().optional(),
    tags: z.array(z.string()).default([]),
    featured: z.boolean().default(false),
    findings: z.array(z.object({
      name: z.string(),
      severity: z.string(),
      score: z.string(),
      advisory: z.string(),
      url: z.string().url(),
    })).default([]),
  }),
});

export const collections = { posts };
