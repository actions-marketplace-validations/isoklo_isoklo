// GitHub Marketplace artwork for the Isoklo listing, generated with sharp:
//
//   node scripts/marketplace-assets.mjs <launch screenshots folder>
//
// Writes marketplace-assets/:
//   logo-200.png               the Isoklo symbol, paper on an ink square (400 x 400: twice GitHub's 200 px minimum).
//                              Set the listing's badge background colour to #11100E so the badge is seamless.
//   feature-card-965x482.png   the feature card background, exactly 965 x 482. No text: GitHub draws the app's logo,
//                              name and short description on top of it, in the text colour chosen in the listing.
//   screenshot-<n>-<name>.png  real screenshots of Isoklo on isoklo-demo, 1600 x 1000 each (GitHub asks for at least
//                              1200 px wide, all the same shape). Each is cropped to the part that matters, with no
//                              browser bar, sidebar, taskbar or frame, and centred on the screenshot's own background
//                              colour, so nothing reads as a border. Nothing inside a crop is edited.
import { mkdirSync, readFileSync, readdirSync } from "node:fs";
import { join } from "node:path";
import sharp from "sharp";

const INK = "#11100E";
const PAPER = "#F7F6F3";
const BRASS = "#B39F77";
const ICE = "#C3D9F3";

const source = process.argv[2];
if (!source) {
  console.error("usage: node scripts/marketplace-assets.mjs <launch screenshots folder>");
  process.exit(2);
}
const here = import.meta.dirname;
const out = join(here, "..", "marketplace-assets");
mkdirSync(out, { recursive: true });

// The symbol, exactly as the brand draws it (viewBox units, centred on 60,60): the curved stem and the dot.
const symbolSvg = readFileSync(join(here, "..", "..", "..", "brand", "logo-final", "isoklo-symbol-paper.svg"), "utf8");
const symbolPaths = /<g[^>]*>([\s\S]*?)<\/g>/.exec(symbolSvg)?.[1];
if (!symbolPaths) throw new Error("could not read the symbol from brand/logo-final/isoklo-symbol-paper.svg");
const strokeStyle = 'fill="none" stroke-linecap="round" stroke-linejoin="round" stroke-width="16"';

// ---------------------------------------------------------------- logo
const logo = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 120 120" width="400" height="400">
  <rect width="120" height="120" fill="${INK}"/>
  <g transform="translate(60 60) scale(0.62) translate(-60 -60)" ${strokeStyle} stroke="${PAPER}">${symbolPaths}</g>
</svg>`;
await sharp(Buffer.from(logo)).png({ compressionLevel: 9 }).toFile(join(out, "logo-200.png"));

// ---------------------------------------------------------------- feature card
// The symbol's construction, drawn large and faint on the right: its two arcs' circles, the axis, the baselines and
// the dot, in the brand's ink, brass and paper. The left two thirds stay calm for GitHub's own logo and text.
const W = 965;
const H = 482;
const S = 3.4; // symbol units to pixels
const cx = 730;
const cy = 250;
const p = (x, y) => [(cx + (x - 60) * S).toFixed(1), (cy + (y - 60) * S).toFixed(1)];
const circle = (x, y, r, attrs) => { const [X, Y] = p(x, y); return `<circle cx="${X}" cy="${Y}" r="${(r * S).toFixed(1)}" ${attrs}/>`; };
const line = (x1, y1, x2, y2, attrs) => { const [a, b] = p(x1, y1); const [c, d] = p(x2, y2); return `<line x1="${a}" y1="${b}" x2="${c}" y2="${d}" ${attrs}/>`; };
const guide = `fill="none" stroke="${BRASS}" stroke-width="1.2" stroke-opacity="0.38"`;
const faint = `fill="none" stroke="${PAPER}" stroke-width="1" stroke-opacity="0.10"`;
const card = `<svg xmlns="http://www.w3.org/2000/svg" width="${W}" height="${H}" viewBox="0 0 ${W} ${H}">
  <defs>
    <radialGradient id="glow" cx="${cx}" cy="${cy}" r="360" gradientUnits="userSpaceOnUse">
      <stop offset="0" stop-color="${ICE}" stop-opacity="0.10"/>
      <stop offset="1" stop-color="${ICE}" stop-opacity="0"/>
    </radialGradient>
  </defs>
  <rect width="${W}" height="${H}" fill="${INK}"/>
  <rect width="${W}" height="${H}" fill="url(#glow)"/>
  ${circle(60, 60, 54, faint)}
  ${circle(60, 60, 36, faint)}
  ${line(60, -40, 60, 160, faint)}
  ${line(-30, 56.28, 150, 56.28, faint)}
  ${line(-30, 90.26, 150, 90.26, faint)}
  ${circle(47.26, 56.28, 12.74, guide)}
  ${circle(72.74, 90.26, 12.74, guide)}
  ${line(47.26, 30, 47.26, 80, guide)}
  ${line(72.74, 66, 72.74, 116, guide)}
  <g transform="translate(${cx} ${cy}) scale(${S}) translate(-60 -60)" ${strokeStyle} stroke="${PAPER}" stroke-opacity="0.16">${symbolPaths}</g>
  ${circle(47.26, 56.28, 0.9, `fill="${BRASS}" fill-opacity="0.8"`)}
  ${circle(72.74, 90.26, 0.9, `fill="${BRASS}" fill-opacity="0.8"`)}
  ${circle(60, 20.19, 0.9, `fill="${BRASS}" fill-opacity="0.8"`)}
</svg>`;
await sharp(Buffer.from(card)).png({ compressionLevel: 9 }).toFile(join(out, "feature-card-965x482.png"));

// ---------------------------------------------------------------- screenshots
const CANVAS = { width: 1600, height: 1000 };
const MARGIN = 64;
const GITHUB_DARK = { r: 13, g: 17, b: 23 }; // sampled from the screenshots' page background
const TERMINAL = { r: 12, g: 12, b: 12 };
// The bot comments are cropped 2 px inside GitHub's card border, so no rounded-corner remnants show.
const SHOTS = [
  { prefix: "01-", name: "required-check", crop: { left: 30, top: 74, width: 1352, height: 696 }, bg: GITHUB_DARK },
  { prefix: "04-", name: "invented-package", crop: { left: 46, top: 271, width: 1319, height: 667 }, bg: GITHUB_DARK },
  { prefix: "03-", name: "inline-annotation", crop: { left: 466, top: 146, width: 1390, height: 784 }, bg: GITHUB_DARK },
  { prefix: "02-", name: "evidence-receipt", crop: { left: 46, top: 198, width: 1319, height: 740 }, bg: GITHUB_DARK },
  // The terminal shot starts below the shell prompt, which showed a local folder path.
  { prefix: "05-", name: "cli-verdict", crop: { left: 0, top: 86, width: 1880, height: 477 }, bg: TERMINAL },
];
const files = readdirSync(source);
for (const [i, shot] of SHOTS.entries()) {
  const file = files.find((f) => f.startsWith(shot.prefix) && /\.png$/i.test(f));
  if (!file) throw new Error(`no screenshot starting with ${shot.prefix} in ${source}`);
  const scale = Math.min(1, (CANVAS.width - 2 * MARGIN) / shot.crop.width, (CANVAS.height - 2 * MARGIN) / shot.crop.height);
  const w = Math.round(shot.crop.width * scale);
  const h = Math.round(shot.crop.height * scale);
  let cut = sharp(join(source, file)).extract(shot.crop);
  if (scale < 1) cut = cut.resize(w, h, { kernel: "lanczos3" });
  const content = await cut.png().toBuffer();
  const name = `screenshot-${i + 1}-${shot.name}.png`;
  const done = await sharp({ create: { ...CANVAS, channels: 3, background: shot.bg } })
    .composite([{ input: content, left: Math.round((CANVAS.width - w) / 2), top: Math.round((CANVAS.height - h) / 2) }])
    .png({ compressionLevel: 9 })
    .toFile(join(out, name));
  console.log(`${name}: ${done.width}x${done.height}, ${(done.size / 1024).toFixed(0)} kB${scale < 1 ? `, content scaled to ${Math.round(scale * 100)}%` : ""}`);
}
for (const f of ["logo-200.png", "feature-card-965x482.png"]) {
  const m = await sharp(join(out, f)).metadata();
  console.log(`${f}: ${m.width}x${m.height}`);
}
