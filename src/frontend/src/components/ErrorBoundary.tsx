import { Component, type ErrorInfo, type ReactNode } from 'react';

interface ErrorBoundaryProps {
  children: ReactNode;
}

interface ErrorBoundaryState {
  error: Error | null;
}

/**
 * Catches render-time exceptions so one bad payload or component degrades to a
 * message instead of a blank page. React Query already surfaces fetch failures;
 * this is the backstop for everything else.
 */
export class ErrorBoundary extends Component<ErrorBoundaryProps, ErrorBoundaryState> {
  state: ErrorBoundaryState = { error: null };

  static getDerivedStateFromError(error: Error): ErrorBoundaryState {
    return { error };
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    console.error('Unhandled render error:', error, info.componentStack);
  }

  render(): ReactNode {
    if (this.state.error) {
      return (
        <div className="min-h-screen bg-[#F6F7F9] p-6">
          <div className="mx-auto max-w-2xl rounded-lg border border-red-200 dark:border-red-500/30 bg-red-50 dark:bg-red-500/10 p-6 text-red-700 dark:text-red-300">
            <h1 className="mb-1 text-lg font-semibold">Something went wrong</h1>
            <p className="text-sm">
              The dashboard hit an unexpected error and could not render this view. Reload the page to try again.
            </p>
            <p className="mt-3 break-all font-mono text-xs opacity-70">{this.state.error.message}</p>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}
