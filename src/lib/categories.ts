import { cache } from "react";
import { db } from "@/db";

/** Cached per-request: all 14 categories, ordered for nav/filter display. Queried from the dashboard layout and several rule pages. */
export const getOrderedCategories = cache(async () => {
  return db.query.categories.findMany({
    orderBy: (c, { asc }) => [asc(c.sortOrder)],
  });
});
