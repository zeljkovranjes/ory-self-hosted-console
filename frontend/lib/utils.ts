import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

// shadcn/ui className helper: clsx for conditional joins + tailwind-merge to
// dedupe conflicting Tailwind utilities (last-wins). Used by every vendored
// component and the three Phase-5 primitives.
export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}
