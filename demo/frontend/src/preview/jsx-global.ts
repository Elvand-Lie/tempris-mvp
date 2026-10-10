// Preview (artifact) build only: automatic JSX runtime mapped onto the React UMD global.
const R = (window as any).React;
export const Fragment = R.Fragment;
export function jsx(type: any, props: any, key?: any) {
  return R.createElement(type, key === undefined ? props : { ...props, key });
}
export const jsxs = jsx;
