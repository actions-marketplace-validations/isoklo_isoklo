/**
 * Optional embedded @font-face rules for the HTML report. Empty by default, to keep the npm package small: the report
 * uses Jost and Atkinson Hyperlegible when they are installed and good system fonts otherwise, and makes no network
 * requests either way. To ship pixel-identical reports, put subset WOFF2 @font-face rules (both families are under the
 * SIL Open Font License) in this string as data: URIs.
 */
export const FONT_FACES = "";
