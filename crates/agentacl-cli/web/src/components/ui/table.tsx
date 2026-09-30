import * as React from 'react'
import { cn } from '@/lib/utils'

export function Table({ className, ...props }: React.ComponentProps<'table'>) {
  return (
    <div className="relative w-full overflow-x-auto">
      <table className={cn('w-full caption-bottom text-sm', className)} {...props} />
    </div>
  )
}
export const TableHeader = ({ className, ...p }: React.ComponentProps<'thead'>) => <thead className={cn('[&_tr]:border-b', className)} {...p} />
export const TableBody = ({ className, ...p }: React.ComponentProps<'tbody'>) => <tbody className={cn('[&_tr:last-child]:border-0', className)} {...p} />
export const TableRow = ({ className, ...p }: React.ComponentProps<'tr'>) => <tr className={cn('border-b transition-colors hover:bg-muted/50 data-[state=selected]:bg-muted', className)} {...p} />
export const TableHead = ({ className, ...p }: React.ComponentProps<'th'>) => (
  <th className={cn('h-10 px-3 text-left align-middle text-xs font-medium whitespace-nowrap text-muted-foreground', className)} {...p} />
)
export const TableCell = ({ className, ...p }: React.ComponentProps<'td'>) => <td className={cn('px-3 py-2.5 align-middle', className)} {...p} />
