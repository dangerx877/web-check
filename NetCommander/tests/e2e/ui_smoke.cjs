// Drives the web dashboard in Chromium: sign-in, every module page, console errors, screenshots.
// usage: node ui_smoke.cjs <base-url> <credentials.json> <screenshot-dir>
const { chromium } = require("playwright");
const crypto = require("crypto");
const fs = require("fs");

function totp(secret) {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let bits = "";
  for (const c of secret.replace(/=+$/, "")) bits += alphabet.indexOf(c).toString(2).padStart(5, "0");
  const key = Buffer.from(bits.match(/.{8}/g).map((b) => parseInt(b, 2)));
  const counter = Buffer.alloc(8); counter.writeBigUInt64BE(BigInt(Math.floor(Date.now() / 30000)));
  const h = crypto.createHmac("sha1", key).update(counter).digest(); const o = h[h.length - 1] & 15;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1e6).padStart(6, "0");
}

(async () => {
  const [base, credFile, out] = process.argv.slice(2);
  const cred = JSON.parse(fs.readFileSync(credFile, "utf8"));
  const browser = await chromium.launch();
  const errors = [];
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 }, deviceScaleFactor: 1, colorScheme: "dark" });
  const page = await ctx.newPage();
  page.on("console", (m) => { if (m.type() === "error" && !m.text().includes("status of 409")) errors.push(m.text()); });
  page.on("pageerror", (e) => errors.push(String(e)));
  await page.goto(base);
  await page.fill("input[name=email]", cred.email);
  await page.fill("input[name=password]", cred.password);
  await page.fill("input[name=otp]", totp(cred.totp));
  await page.click("button[type=submit]");
  await page.waitForSelector("#app:not(.hidden)");
  errors.length = 0;               // the 401 from the pre-sign-in session probe is expected
  await page.waitForSelector(".score");
  await page.screenshot({ path: `${out}/dashboard-dark.png`, fullPage: true });
  const pages = ["inventory", "discovery", "servers", "virtualization", "containers", "storage", "network", "monitoring", "automation", "backups", "integrations", "security"];
  const results = {};
  for (const p of pages) {
    await page.evaluate((h) => { location.hash = h; }, p);
    await page.waitForTimeout(700);
    const text = await page.textContent("#view");
    results[p] = text.includes("Loading…") ? "STILL LOADING" : (await page.$("#view .card.error")) ? "ERROR: " + text.slice(0, 200) : "ok";
    if (["inventory", "storage", "virtualization", "network", "automation", "containers"].includes(p)) await page.screenshot({ path: `${out}/${p}.png`, fullPage: true });
  }
  // drill into an asset and the automation approval list
  await page.evaluate(() => { location.hash = "inventory"; }); await page.waitForTimeout(500);
  await page.click("#inv-table tbody tr.click"); await page.waitForTimeout(800);
  results["asset-detail"] = (await page.textContent("#view")).includes("Latest metrics") ? "ok" : "missing";
  await page.screenshot({ path: `${out}/asset.png`, fullPage: true });
  // confirmation dialog for a destructive action
  await page.evaluate(() => { location.hash = "virtualization"; }); await page.waitForTimeout(700);
  await page.click('button[data-act="stop"]'); await page.waitForSelector("dialog[open]");
  results["confirm-dialog"] = (await page.textContent("#modal-body")).includes("destructive") ? "ok" : "missing";
  await page.screenshot({ path: `${out}/confirm.png` });
  await page.click("#modal-cancel");
  // light theme + phone width
  await page.click("#theme-btn"); await page.evaluate(() => { location.hash = "dashboard"; }); await page.waitForTimeout(700);
  await page.screenshot({ path: `${out}/dashboard-light.png`, fullPage: true });
  await page.setViewportSize({ width: 390, height: 844 }); await page.waitForTimeout(300);
  const overflow = await page.evaluate(() => document.documentElement.scrollWidth - window.innerWidth);
  results["phone-overflow-px"] = overflow;
  await page.screenshot({ path: `${out}/phone.png`, fullPage: false });
  await page.click("#menu-btn"); await page.waitForTimeout(300);
  await page.screenshot({ path: `${out}/phone-menu.png` });
  await page.click("#logout-btn"); await page.waitForSelector("#login:not(.hidden)");
  results.logout = "ok";
  console.log(JSON.stringify({ results, errors }, null, 2));
  await browser.close();
  process.exit(errors.length || Object.values(results).some((v) => typeof v === "string" && v !== "ok") || overflow > 0 ? 1 : 0);
})();
