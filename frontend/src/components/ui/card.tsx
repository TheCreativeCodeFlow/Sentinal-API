import { cn } from "@/lib/utils";

export interface CardHeaderProps {
  className?: string;
  children: React.ReactNode;
}

export interface CardTitleProps {
  className?: string;
  children: React.ReactNode;
}

export interface CardContentProps {
  className?: string;
  children: React.ReactNode;
}

export function CardHeader({ className, children }: CardHeaderProps) {
  return (
    <div className={cn("py-2 px-6 text-xs font-medium text-muted-foreground", className)}>
      {children}
    </div>
  );
}

export function CardTitle({ className, children }: CardTitleProps) {
  return (
    <h3 className={cn("text-xl font-semibold whitespace-nowrap", className)}>
      {children}
    </h3>
  );
}

export function CardContent({ className, children }: CardContentProps) {
  return (
    <div className={cn("px-6 pb-6", className)}>
      {children}
    </div>
  );
}

export interface CardProps {
  className?: string;
  children: React.ReactNode;
}

export function Card({ className, children }: CardProps) {
  return (
    <div className={cn(
      "rounded-lg border border-border bg-card p-6 shadow-sm",
      className,
    )}>
      {children}
    </div>
  );
}