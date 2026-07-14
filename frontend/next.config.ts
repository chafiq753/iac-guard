import type { NextConfig } from "next";

const nextConfig: NextConfig = {
  // Pin the workspace root: unrelated lockfiles exist higher up the tree
  // (e.g. in the home directory), which Next would otherwise auto-detect.
  turbopack: {
    root: __dirname,
  },
};

export default nextConfig;
