"use client";

import type { ReactNode } from "react";
import { motion } from "motion/react";

const container = {
  hidden: {},
  show: {
    transition: { staggerChildren: 0.04 },
  },
};

const item = {
  hidden: { opacity: 0, y: 8 },
  show: { opacity: 1, y: 0 },
};

export function RuleGrid({ children }: { children: ReactNode[] }) {
  return (
    <motion.div
      initial="hidden"
      animate="show"
      variants={container}
      className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3"
    >
      {children.map((child, i) => (
        <motion.div
          key={i}
          variants={item}
          transition={{ duration: 0.2, ease: "easeOut" }}
        >
          {child}
        </motion.div>
      ))}
    </motion.div>
  );
}
