// Preview (artifact) build only: react-dom/client from the UMD global.
const D = (window as any).ReactDOM;
export const createRoot = D.createRoot;
export default D;
