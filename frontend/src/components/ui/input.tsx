import { cn } from "@/lib/utils";

export interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  type?: string;
}

export function Input(props: InputProps) {
  const { type = "text", className, ...rest } = props;
  return (
    <input
      type={type}
      className={cn(
        "block w-full rounded-md border px-3 py-2 placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2",
        "placeholder-muted",
        className,
      )}
      {...rest}
    />
  );
}