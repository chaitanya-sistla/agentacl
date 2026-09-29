import * as React from 'react'
import * as D from '@radix-ui/react-dialog'
import { X } from 'lucide-react'
import { cn } from '@/lib/utils'

export const Dialog = D.Root
export const DialogTrigger = D.Trigger
export const DialogClose = D.Close

export function DialogContent({ className, children, wide, ...props }: React.ComponentProps<typeof D.Content> & { wide?: boolean }) {
  return (
    <D.Portal>
      <D.Overlay className="fixed inset-0 z-50 bg-black/50 backdrop-blur-[2px]" />
      <D.Content
        className={cn(
          'fixed top-1/2 left-1/2 z-50 grid max-h-[88vh] w-[calc(100%-2rem)] -translate-x-1/2 -translate-y-1/2 gap-4 overflow-y-auto rounded-xl border bg-background p-6 shadow-2xl',
          wide ? 'max-w-3xl' : 'max-w-lg',
          className,
        )}
        {...props}
      >
        {children}
        <D.Close className="absolute top-4 right-4 rounded-sm opacity-60 transition-opacity hover:opacity-100 focus:outline-none">
          <X className="size-4" />
          <span className="sr-only">Close</span>
        </D.Close>
      </D.Content>
    </D.Portal>
  )
}
export const DialogHeader = ({ className, ...p }: React.ComponentProps<'div'>) => <div className={cn('flex flex-col gap-1.5 pr-6', className)} {...p} />
export const DialogFooter = ({ className, ...p }: React.ComponentProps<'div'>) => <div className={cn('flex flex-col-reverse gap-2 sm:flex-row sm:justify-end', className)} {...p} />
export const DialogTitle = ({ className, ...p }: React.ComponentProps<typeof D.Title>) => <D.Title className={cn('text-lg font-semibold leading-none', className)} {...p} />
export const DialogDescription = ({ className, ...p }: React.ComponentProps<typeof D.Description>) => <D.Description className={cn('text-sm text-muted-foreground', className)} {...p} />

/** Right-side panel (shadcn "Sheet"). */
export function SheetContent({ className, children, ...props }: React.ComponentProps<typeof D.Content>) {
  return (
    <D.Portal>
      <D.Overlay className="fixed inset-0 z-50 bg-black/40" />
      <D.Content className={cn('fixed inset-y-0 right-0 z-50 flex h-full w-full max-w-xl flex-col gap-4 overflow-y-auto border-l bg-background p-6 shadow-2xl', className)} {...props}>
        {children}
        <D.Close className="absolute top-4 right-4 rounded-sm opacity-60 transition-opacity hover:opacity-100">
          <X className="size-4" />
        </D.Close>
      </D.Content>
    </D.Portal>
  )
}
