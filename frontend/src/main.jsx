import React from "react";
import ReactDOM from "react-dom/client";
import App from "./App.jsx";
import "./index.css";

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null, errorInfo: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error("ErrorBoundary caught an unhandled error:", error, errorInfo);
    this.setState({ errorInfo });
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{ padding: 32, background: "#0a0c10", color: "#f43f5e", fontFamily: "sans-serif", minHeight: "100vh" }}>
          <h2 style={{ color: "#f43f5e", marginBottom: 12 }}>Application Runtime Error</h2>
          <div style={{ background: "#181d26", padding: 16, borderRadius: 6, color: "#fff", fontFamily: "monospace", fontSize: 13, whiteSpace: "pre-wrap", border: "1px solid rgba(244, 63, 94, 0.4)" }}>
            {this.state.error?.toString()}
          </div>
          {this.state.errorInfo?.componentStack && (
            <pre style={{ marginTop: 12, fontSize: 11, color: "#94a3b8", overflowX: "auto" }}>
              {this.state.errorInfo.componentStack}
            </pre>
          )}
          <button
            onClick={() => window.location.reload()}
            style={{ marginTop: 16, padding: "8px 16px", background: "#0ea5e9", color: "#fff", border: "none", borderRadius: 4, cursor: "pointer", fontWeight: 600 }}
          >
            Reload Console
          </button>
        </div>
      );
    }
    return this.props.children;
  }
}

ReactDOM.createRoot(document.getElementById("root")).render(
  <React.StrictMode>
    <ErrorBoundary>
      <App />
    </ErrorBoundary>
  </React.StrictMode>
);