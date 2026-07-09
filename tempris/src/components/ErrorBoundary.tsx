import { Component, type ReactNode } from 'react';
import { AlertTriangle, RefreshCw } from 'lucide-react';

interface Props {
  children: ReactNode;
  moduleName?: string;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

/**
 * Error Boundary — catches render errors per-module with graceful fallback.
 * Prevents a single component crash from taking down the entire app.
 */
export default class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, info: React.ErrorInfo) {
    console.error(`[ErrorBoundary] ${this.props.moduleName || 'Module'} crashed:`, error, info);
    
    // Report error to audit log via API (best-effort)
    try {
      fetch('/api/audit/log', {
        method: 'POST',
        credentials: 'include',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          action: 'FRONTEND_ERROR',
          module: this.props.moduleName || 'UNKNOWN',
          detail: `Component crash: ${error.message}`,
        }),
      }).catch(() => {}); // Ignore reporting failures
    } catch {} // Ignore all reporting errors
  }

  handleReload = () => {
    this.setState({ hasError: false, error: null });
  };

  render() {
    if (this.state.hasError) {
      return (
        <div className="p-8 flex flex-col items-center justify-center min-h-[400px] animate-in fade-in">
          <div className="glass-panel p-8 max-w-md text-center space-y-4">
            <div className="w-16 h-16 rounded-full bg-danger/10 flex items-center justify-center mx-auto">
              <AlertTriangle size={32} className="text-danger" />
            </div>
            <h2 className="text-xl font-bold text-text-main">
              {this.props.moduleName || 'Module'} Error
            </h2>
            <p className="text-text-muted text-sm">
              An unexpected error occurred in this module. Your data is safe — this is an isolated component failure.
            </p>
            {this.state.error && (
              <pre className="text-xs text-danger/70 bg-danger/5 rounded-lg p-3 overflow-auto max-h-24 text-left border border-danger/10">
                {this.state.error.message}
              </pre>
            )}
            <button
              onClick={this.handleReload}
              className="flex items-center gap-2 mx-auto px-4 py-2 bg-primary-500/10 text-primary-400 rounded-lg border border-primary-500/20 hover:bg-primary-500/20 transition-colors text-sm font-medium"
            >
              <RefreshCw size={16} />
              Retry Module
            </button>
          </div>
        </div>
      );
    }

    return this.props.children;
  }
}

