import * as React from 'react'
import * as T from '@radix-ui/react-tabs'
import { cn } from '@/lib/utils'

export const Tabs = ({ className, ...p }: React.ComponentProps<typeof T.Root>) => <T.Root className={cn('flex flex-col gap-4', className)} {...p} />
export const TabsList = ({ className, ...p }: React.ComponentProps<typeof T.List>) => (
  <T.List className={cn('inline-flex h-9 w-fit items-center rounded-lg bg-muted p-[3px] text-muted-foreground', className)} {...p} />
)
export const TabsTrigger = ({ className, ...p }: React.ComponentProps<typeof T.Trigger>) => (
  <T.Trigger
    className={cn(
      "inline-flex h-full items-center justify-center gap-1.5 rounded-md px-3 text-sm font-medium whitespace-nowrap transition-all data-[state=active]:bg-background data-[state=active]:text-foreground data-[state=active]:shadow-sm dark:data-[state=active]:bg-input/40 [&_svg:not([class*='size-'])]:size-4 cursor-pointer",
      className,
    )}
    {...p}
  />
)
export const TabsContent = ({ className, ...p }: React.ComponentProps<typeof T.Content>) => <T.Content className={cn('outline-none', className)} {...p} />
