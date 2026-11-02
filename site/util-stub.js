// near-api-js 間接引用 Node 的 util（generate-function 只用 format）；瀏覽器用這個替代
export function format(f, ...a) {
  let i = 0;
  return String(f).replace(/%[sdj]/g, () => String(a[i++]));
}
export default { format };
