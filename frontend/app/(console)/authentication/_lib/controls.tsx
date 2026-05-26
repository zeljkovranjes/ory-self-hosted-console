"use client";

// Phase 7 — small RHF-bound controls for the scalar config pages. Each control
// is keyed by a JSON-Pointer (the form field name) so the form values map 1:1
// to the section's allowlisted pointers (the flat PUT body). Inline Zod errors
// render under each control via FormMessage-style text.

import type { FieldValues, Path, UseFormReturn } from "react-hook-form";

import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";

type AnyForm<T extends FieldValues> = UseFormReturn<T, unknown, FieldValues>;

function errorFor<T extends FieldValues>(
  form: AnyForm<T>,
  pointer: string,
): string | undefined {
  const err = form.formState.errors[pointer as keyof T];
  const msg = (err as { message?: unknown } | undefined)?.message;
  return typeof msg === "string" ? msg : undefined;
}

function safeId(pointer: string): string {
  return `f${pointer.replace(/[^a-zA-Z0-9]+/g, "-")}`;
}

export function PointerSwitch<T extends FieldValues>({
  form,
  pointer,
  label,
  description,
}: {
  form: AnyForm<T>;
  pointer: string;
  label: string;
  description?: string;
}) {
  const id = safeId(pointer);
  const error = errorFor(form, pointer);
  return (
    <div className="flex items-start justify-between gap-4">
      <div className="grid gap-0.5">
        <Label htmlFor={id}>{label}</Label>
        {description ? (
          <p className="text-muted-foreground text-sm">{description}</p>
        ) : null}
        {error ? <p className="text-destructive text-sm">{error}</p> : null}
      </div>
      <Switch
        id={id}
        aria-label={label}
        checked={Boolean(form.watch(pointer as Path<T>))}
        onCheckedChange={(v) =>
          form.setValue(pointer as Path<T>, v as never, { shouldDirty: true })
        }
      />
    </div>
  );
}

export function PointerText<T extends FieldValues>({
  form,
  pointer,
  label,
  description,
  placeholder,
  type = "text",
}: {
  form: AnyForm<T>;
  pointer: string;
  label: string;
  description?: string;
  placeholder?: string;
  type?: string;
}) {
  const id = safeId(pointer);
  const error = errorFor(form, pointer);
  return (
    <div className="grid gap-2">
      <Label htmlFor={id}>{label}</Label>
      <Input
        id={id}
        type={type}
        aria-label={label}
        placeholder={placeholder}
        {...form.register(pointer as Path<T>)}
      />
      {description ? (
        <p className="text-muted-foreground text-sm">{description}</p>
      ) : null}
      {error ? <p className="text-destructive text-sm">{error}</p> : null}
    </div>
  );
}

export function PointerSelect<T extends FieldValues>({
  form,
  pointer,
  label,
  options,
  description,
}: {
  form: AnyForm<T>;
  pointer: string;
  label: string;
  options: readonly string[];
  description?: string;
}) {
  const id = safeId(pointer);
  const error = errorFor(form, pointer);
  const value = form.watch(pointer as Path<T>) as string | undefined;
  return (
    <div className="grid gap-2">
      <Label htmlFor={id}>{label}</Label>
      <Select
        value={value ?? ""}
        onValueChange={(v) =>
          form.setValue(pointer as Path<T>, v as never, { shouldDirty: true })
        }
      >
        <SelectTrigger id={id} aria-label={label}>
          <SelectValue placeholder="Select…" />
        </SelectTrigger>
        <SelectContent>
          {options.map((opt) => (
            <SelectItem key={opt} value={opt}>
              {opt}
            </SelectItem>
          ))}
        </SelectContent>
      </Select>
      {description ? (
        <p className="text-muted-foreground text-sm">{description}</p>
      ) : null}
      {error ? <p className="text-destructive text-sm">{error}</p> : null}
    </div>
  );
}

/**
 * A simple add/remove editor for an array-of-strings pointer (passkey/webauthn
 * origins). Renders one input per entry plus add/remove buttons. The value is a
 * `string[]` bound to the pointer field.
 */
export function PointerStringList<T extends FieldValues>({
  form,
  pointer,
  label,
  description,
  placeholder,
}: {
  form: AnyForm<T>;
  pointer: string;
  label: string;
  description?: string;
  placeholder?: string;
}) {
  const id = safeId(pointer);
  const error = errorFor(form, pointer);
  const raw = form.watch(pointer as Path<T>);
  const items: string[] = Array.isArray(raw) ? (raw as string[]) : [];

  function commit(next: string[]) {
    form.setValue(pointer as Path<T>, next as never, { shouldDirty: true });
  }

  return (
    <div className="grid gap-2">
      <Label htmlFor={`${id}-0`}>{label}</Label>
      {description ? (
        <p className="text-muted-foreground text-sm">{description}</p>
      ) : null}
      <div className="grid gap-2">
        {items.map((entry, i) => (
          <div key={i} className="flex gap-2">
            <Input
              id={`${id}-${i}`}
              aria-label={`${label} ${i + 1}`}
              placeholder={placeholder}
              value={entry}
              onChange={(e) => {
                const next = [...items];
                next[i] = e.target.value;
                commit(next);
              }}
            />
            <button
              type="button"
              className="text-destructive text-sm underline"
              aria-label={`Remove ${label} ${i + 1}`}
              onClick={() => commit(items.filter((_, j) => j !== i))}
            >
              Remove
            </button>
          </div>
        ))}
      </div>
      <button
        type="button"
        className="text-sm underline self-start"
        onClick={() => commit([...items, ""])}
      >
        Add {label}
      </button>
      {error ? <p className="text-destructive text-sm">{error}</p> : null}
    </div>
  );
}
