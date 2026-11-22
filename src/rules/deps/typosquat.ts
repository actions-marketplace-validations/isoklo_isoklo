/**
 * deps/typosquat: a new package whose name is one typo away from a very popular one. Works offline. Names are compared
 * after npm/PyPI normalisation, with one insertion, deletion, substitution or swap of neighbours (Damerau-Levenshtein
 * distance 1), or with only separators differing (socket-io vs socket.io). Popular names that are themselves close to
 * each other (react, preact; redis, redux) are all on the list, so they never flag one another.
 */
import type { Ecosystem } from "../../check/packages/manifests.js";

const NPM_POPULAR = [
  "react", "react-dom", "preact", "vue", "svelte", "next", "nuxt", "express", "koa", "fastify", "hono", "lodash", "underscore",
  "axios", "node-fetch", "cross-fetch", "got", "superagent", "request", "moment", "dayjs", "date-fns", "luxon", "chalk",
  "colors", "color", "commander", "yargs", "minimist", "inquirer", "ora", "debug", "dotenv", "cors", "body-parser",
  "cookie-parser", "express-session", "helmet", "morgan", "winston", "pino", "bunyan", "mongoose", "mongodb", "mysql",
  "mysql2", "sqlite3", "better-sqlite3", "redis", "ioredis", "redux", "react-redux", "mobx", "rxjs", "zod", "yup", "joi",
  "ajv", "uuid", "nanoid", "classnames", "clsx", "prop-types", "webpack", "rollup", "esbuild", "vite", "vitest", "jest",
  "mocha", "chai", "sinon", "cypress", "playwright", "puppeteer", "puppeteer-core", "typescript", "eslint", "prettier",
  "babel-core", "nodemon", "concurrently", "cross-env", "husky", "lint-staged", "ts-node", "tsx", "tailwindcss",
  "postcss", "autoprefixer", "sass", "less", "styled-components", "immer", "immutable", "graphql", "socket.io",
  "socket.io-client", "ws", "jsonwebtoken", "bcrypt", "bcryptjs", "passport", "nodemailer", "cheerio", "sharp", "jimp",
  "multer", "glob", "rimraf", "mkdirp", "fs-extra", "semver", "lru-cache", "qs", "form-data", "mime", "mime-types",
  "js-yaml", "yaml", "xml2js", "handlebars", "ejs", "pug", "marked", "highlight.js", "three", "d3", "chart.js",
  "electron", "sequelize", "prisma", "knex", "typeorm", "crypto-js", "bignumber.js", "decimal.js", "validator", "jquery",
  "bootstrap", "framer-motion", "gsap", "discord.js", "stripe", "openai", "langchain", "firebase", "aws-sdk", "twilio",
  "event-stream", "ua-parser-js", "node-ipc", "coa", "rc", "async", "bluebird", "compression", "react-router",
  "react-router-dom", "formik", "react-hook-form", "swr", "vuex", "pinia", "angular", "lit", "solid-js", "astro",
  "remix", "gatsby", "storybook", "babel-loader", "css-loader", "style-loader", "file-loader", "html-webpack-plugin",
  "dotenv-expand", "envalid", "ramda", "fp-ts", "date-fns-tz", "numeral", "accounting", "papaparse", "xlsx", "pdfkit",
  "jspdf", "canvas", "qrcode", "nock", "supertest", "msw", "faker", "@faker-js/faker", "ethers", "web3", "viem",
];

const PYPI_POPULAR = [
  "requests", "numpy", "pandas", "scipy", "matplotlib", "seaborn", "plotly", "django", "flask", "fastapi", "uvicorn",
  "gunicorn", "starlette", "pydantic", "sqlalchemy", "alembic", "boto3", "botocore", "urllib3", "six", "setuptools",
  "wheel", "pip", "certifi", "idna", "charset-normalizer", "chardet", "python-dateutil", "pytz", "pyyaml", "jinja2",
  "markupsafe", "click", "typer", "rich", "attrs", "packaging", "cryptography", "pyopenssl", "rsa", "pyjwt", "jwt",
  "beautifulsoup4", "bs4", "lxml", "pillow", "opencv-python", "tensorflow", "torch", "torchvision", "keras",
  "scikit-learn", "transformers", "tokenizers", "datasets", "openai", "anthropic", "langchain", "tqdm", "colorama",
  "psycopg2", "psycopg2-binary", "psycopg", "pymongo", "redis", "celery", "kombu", "pytest", "pytest-cov", "coverage",
  "black", "flake8", "mypy", "ruff", "isort", "pylint", "httpx", "aiohttp", "websockets", "selenium", "paramiko",
  "docker", "kubernetes", "google-cloud-storage", "grpcio", "protobuf", "jsonschema", "toml", "tomli", "typing-extensions",
  "networkx", "sympy", "nltk", "spacy", "gensim", "xgboost", "lightgbm", "streamlit", "dash", "werkzeug", "itsdangerous",
  "python-dotenv", "dotenv", "pyserial", "pygame", "scrapy", "tornado", "twisted", "pymysql", "mysqlclient", "simplejson",
  "ujson", "orjson", "arrow", "pendulum", "marshmallow", "wtforms", "loguru", "sentry-sdk", "stripe", "twilio",
];

const normalize = (e: Ecosystem, name: string) => (e === "pypi" ? name.toLowerCase().replace(/[-_.]+/g, "-") : name.toLowerCase());
const stripSeparators = (s: string) => s.replace(/[-_.]/g, "");

const POPULAR: Record<Ecosystem, Set<string>> = {
  npm: new Set(NPM_POPULAR.map((n) => normalize("npm", n))),
  pypi: new Set(PYPI_POPULAR.map((n) => normalize("pypi", n))),
};

/** Optimal string alignment distance, stopping early once it exceeds 1. */
function withinOne(a: string, b: string): boolean {
  if (Math.abs(a.length - b.length) > 1) return false;
  if (a.length === b.length) {
    const diffs: number[] = [];
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) diffs.push(i);
    if (diffs.length <= 1) return true;
    const [i, j] = diffs as [number, number];
    return diffs.length === 2 && j === i + 1 && a[i] === b[j] && a[j] === b[i];
  }
  const [short, long] = a.length < b.length ? [a, b] : [b, a];
  let i = 0;
  while (i < short.length && short[i] === long[i]) i++;
  return short.slice(i) === long.slice(i + 1);
}

/** The popular package this name imitates, or null. */
export function typosquatOf(ecosystem: Ecosystem, name: string): string | null {
  const n = normalize(ecosystem, name);
  const popular = POPULAR[ecosystem];
  if (popular.has(n)) return null;
  // Scoped npm names are owned by their scope; compare only unscoped names.
  if (n.startsWith("@")) return null;
  for (const p of popular) {
    if (p.startsWith("@")) continue;
    if (Math.min(n.length, p.length) < 4) continue;
    if (withinOne(n, p) || (stripSeparators(n) === stripSeparators(p) && n !== p)) return p;
  }
  return null;
}
