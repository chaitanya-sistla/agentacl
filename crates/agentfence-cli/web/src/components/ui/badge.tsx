import * as React from 'react'
import { cva, type VariantProps } from 'class-variance-authority'
import { cn } from '@/lib/utils'

const badgeVariants = cva('inline-flex items-center gap-1 rounded-md border px-2 py-0.5 text-xs font-medium whitespace-nowrap [&>svg]:size-3', {
  variants: {
    variant: {
      default: 'border-transparent bg-primary text-primary-foreground',
      secondary: 'border-transparent bg-secondary text-secondary-foreground',
      outline: 'text-foreground',
      success: 'border-emerald-500/25 bg-emerald-500/10 text-emerald-700 dark:text-emerald-400',
      danger: 'border-red-500/25 bg-red-500/10 text-red-700 dark:text-red-400',
      warning: 'border-amber-500/25 bg-amber-500/10 text-amber-700 dark:text-amber-400',
      info: 'border-sky-500/25 bg-sky-500/10 text-sky-700 dark:text-sky-400',
      violet: 'border-violet-500/25 bg-violet-500/10 text-violet-700 dark:text-violet-400',
    },
  },
  defaultVariants: { variant: 'default' },
})

export type BadgeVariant = VariantProps<typeof badgeVariants>['variant']

export function Badge({ className, variant, ...props }: React.ComponentProps<'span'> & VariantProps<typeof badgeVariants>) {
  return <span className={cn(badgeVariants({ variant }), className)} {...props} />
}
