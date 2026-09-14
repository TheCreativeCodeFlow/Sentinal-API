import { cn } from "@/lib/utils";

export interface SelectItemProps
  extends React.ComponentPropsWithoutRef<"option"> {
  value: string;
}

export interface SelectProps extends React.HTMLAttributes<HTMLDivElement> {
  value: string;
  onValueChange: (value: string) => void;
  items: SelectItemProps[];
  placeholder?: string;
}

export function Select(props: SelectProps) {
  const { value, onValueChange, items, placeholder = "Select an option", className } = props;
  return (
    <div className={cn("relative w-full rounded-md border px-3 py-2 placeholder:text-muted-foreground focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring focus-visible:ring-offset-2", className)}>
      <div className="flex items-center pointer-events-none">
        <span className="text-sm color-muted-foreground">{placeholder}</span>
      </div>
      <button
        onClick={() => onValueChange(items[0]?.value || "")}
        className="absolute right-2 text-muted-foreground hover:text-foreground"
      >
        ▼
      </button>
      <SelectContent items={items} onValueChange={onValueChange} value={value} />
    </div>
  );
}

interface SelectContentProps {
  items: SelectItemProps[];
  onValueChange: (value: string) => void;
  value: string;
}

function SelectContent({ items, onValueChange, value }: SelectContentProps) {
  return (
    <div
      className={cn(
        "absolute z-10 w-64 rounded-md bg-card border border-border max-h-80 overflow-y-auto shadow-md",
        "motion-safe",
      )}
    >
      {items.map((item) => (
        <button
          key={item.value}
          onClick={() => onValueChange(item.value)}
          className={cn(
            "flex cursor-pointer select-none items-center rounded-sm px-2 py-1.5 text-sm select-none outline-none hover:bg-accent hover:text-accent-foreground data-[disabled]:pointer-events-none data-[disabled]:opacity-50",
            "motion-safe",
          )}
        >
          {item.label || item.value}
        </button>
      ))}
    </div>
  );
}