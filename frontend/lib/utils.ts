import { type ClassValue, clsx } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatNumber(value: number | null | undefined) {
  if (value === null || value === undefined || Number.isNaN(value)) return "—";
  return new Intl.NumberFormat("en-US").format(value);
}

export function formatDate(value: string | null | undefined) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("en-US", {
    month: "short",
    day: "numeric",
    year: "numeric",
    hour: "2-digit",
    minute: "2-digit"
  }).format(date);
}

export function formatRelative(value: string | null | undefined) {
  if (!value) return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  const seconds = Math.round((date.getTime() - Date.now()) / 1000);
  const absolute = Math.abs(seconds);
  if (absolute < 60) return "just now";
  const minutes = Math.round(seconds / 60);
  if (Math.abs(minutes) < 60) return minutes > 0 ? `in ${minutes}m` : `${Math.abs(minutes)}m ago`;
  const hours = Math.round(minutes / 60);
  if (Math.abs(hours) < 24) return hours > 0 ? `in ${hours}h` : `${Math.abs(hours)}h ago`;
  const days = Math.round(hours / 24);
  return days > 0 ? `in ${days}d` : `${Math.abs(days)}d ago`;
}

export function titleCase(value: unknown) {
  if (value === null || value === undefined || value === "") return "—";
  return String(value).replace(/[_-]/g, " ").replace(/\b\w/g, (letter) => letter.toUpperCase());
}

export function truncate(value: string | null | undefined, length = 36) {
  if (!value) return "—";
  return value.length > length ? `${value.slice(0, length - 1)}…` : value;
}

export function isTerminalStatus(status: string | null | undefined) {
  return ["completed", "complete", "failed", "cancelled", "canceled"].includes((status || "").toLowerCase());
}
