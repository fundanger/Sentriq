"use client";

import { useState } from "react";
import Link from "next/link";
import { ArrowLeft } from "lucide-react";
import { Button } from "@/components/ui/button";

export const LIBRARY_QUERY_STORAGE_KEY = "rules-library-query";

export function BackToLibraryLink() {
  const [href] = useState(() => {
    if (typeof window === "undefined") return "/rules";
    const query = sessionStorage.getItem(LIBRARY_QUERY_STORAGE_KEY);
    return query ? `/rules?${query}` : "/rules";
  });

  return (
    <Button variant="ghost" size="sm" className="w-fit" render={<Link href={href} />}>
      <ArrowLeft />
      Back to library
    </Button>
  );
}
