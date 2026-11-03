// near-api-js indirectly references Node's util (generate-function uses only format); the browser uses this as a replacement
export function format(f, ...a) {
  let i = 0;
  return String(f).replace(/%[sdj]/g, () => String(a[i++]));
}
export default { format };
