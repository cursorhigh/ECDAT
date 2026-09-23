export function Checkbox({ className, ...props }: React.InputHTMLAttributes<HTMLInputElement>) {
  return <input type="checkbox" className={`h-4 w-4 shrink-0 accent-primary ${className || ""}`} {...props} />;
}
