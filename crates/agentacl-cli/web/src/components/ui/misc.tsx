import * as React from 'react'
import * as Tip from '@radix-ui/react-tooltip'
import * as Sw from '@radix-ui/react-switch'
import * as DM from '@radix-ui/react-dropdown-menu'
import { cn } from '@/lib/utils'

export function Tooltip({ content, children }: { content: React.ReactNode; children: React.ReactNode }) {
  if (!content) return <>{children}</>
  return (
    <Tip.Root delayDuration={250}>
      <Tip.Trigger asChild>{children}</Tip.Trigger>
      <Tip.Portal>
        <Tip.Content sideOffset={6} className="z-50 max-w-xs rounded-md bg-primary px-3 py-1.5 text-xs text-primary-foreground shadow-md">
          {content}
        </Tip.Content>
      </Tip.Portal>
    </Tip.Root>
  )
}
export const TooltipProvider = Tip.Provider

export function Switch({ className, ...props }: React.ComponentProps<typeof Sw.Root>) {
  return (
    <Sw.Root
      className={cn('peer inline-flex h-5 w-9 shrink-0 cursor-pointer items-center rounded-full border border-transparent shadow-xs transition-all outline-none data-[state=checked]:bg-brand data-[state=unchecked]:bg-input disabled:cursor-not-allowed disabled:opacity-50', className)}
      {...props}
    >
      <Sw.Thumb className="pointer-events-none block size-4 rounded-full bg-background ring-0 transition-transform data-[state=checked]:translate-x-[calc(100%-2px)] data-[state=unchecked]:translate-x-0" />
    </Sw.Root>
  )
}

export function Separator({ className, vertical }: { className?: string; vertical?: boolean }) {
  return <div className={cn('shrink-0 bg-border', vertical ? 'h-full w-px' : 'h-px w-full', className)} />
}

export function Skeleton({ className }: { className?: string }) {
  return <div className={cn('animate-pulse rounded-md bg-muted', className)} />
}

export const DropdownMenu = DM.Root
export const DropdownMenuTrigger = DM.Trigger
export function DropdownMenuContent({ className, ...p }: React.ComponentProps<typeof DM.Content>) {
  return (
    <DM.Portal>
      <DM.Content sideOffset={4} align="end" className={cn('z-50 min-w-44 overflow-hidden rounded-md border bg-popover p-1 text-popover-foreground shadow-md', className)} {...p} />
    </DM.Portal>
  )
}
export function DropdownMenuItem({ className, destructive, ...p }: React.ComponentProps<typeof DM.Item> & { destructive?: boolean }) {
  return (
    <DM.Item
      className={cn("relative flex cursor-pointer items-center gap-2 rounded-sm px-2 py-1.5 text-sm outline-none select-none focus:bg-accent data-[disabled]:pointer-events-none data-[disabled]:opacity-50 [&_svg:not([class*='size-'])]:size-4", destructive && 'text-destructive focus:text-destructive', className)}
      {...p}
    />
  )
}
export const DropdownMenuSeparator = ({ className }: { className?: string }) => <DM.Separator className={cn('-mx-1 my-1 h-px bg-border', className)} />

export function Alert({ className, variant = 'default', ...props }: React.ComponentProps<'div'> & { variant?: 'default' | 'warning' | 'danger' | 'info' }) {
  const v = {
    default: 'bg-card',
    warning: 'border-amber-500/30 bg-amber-500/[0.06] text-amber-900 dark:text-amber-200',
    danger: 'border-red-500/30 bg-red-500/[0.06] text-red-900 dark:text-red-200',
    info: 'border-sky-500/30 bg-sky-500/[0.06] text-sky-900 dark:text-sky-200',
  }[variant]
  return <div role="alert" className={cn("relative grid w-full grid-cols-[auto_1fr] items-start gap-x-3 gap-y-0.5 rounded-lg border px-4 py-3 text-sm [&>svg]:mt-0.5 [&>svg]:size-4", v, className)} {...props} />
}
