// Preview (artifact) build only: React is loaded as a UMD global from cdnjs.
const R = (window as any).React;
export default R;
export const { useState, useEffect, useMemo, useCallback, useRef, createContext, useContext, StrictMode, Fragment } = R;
