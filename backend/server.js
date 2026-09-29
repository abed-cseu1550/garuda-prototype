import crypto from "node:crypto";
import express from "express";
import { Octokit } from "@octokit/rest";
import { createAppAuth } from "@octokit/auth-app";

const app = express();
const port = Number(process.env.PORT || 10000);

function verifySignature(rawBody, supplied) {
  const secret = process.env.GITHUB_WEBHOOK_SECRET;
  if (!secret || !supplied?.startsWith("sha256=")) return false;
  const expected = `sha256=${crypto.createHmac("sha256", secret).update(rawBody).digest("hex")}`;
  const a = Buffer.from(expected);
  const b = Buffer.from(supplied);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

function scanPatch(filename, patch = "") {
  if (!patch || /(^|\/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml)$/i.test(filename)) return [];
  const found = [];
  let newLine = 0;
  for (const line of patch.split("\n")) {
    const hunk = line.match(/^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@/);
    if (hunk) {
      newLine = Number(hunk[1]);
      continue;
    }
    if (line.startsWith("+") && !line.startsWith("+++")) {
      const code = line.slice(1);
      if (/(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})/.test(code)) {
        found.push({ path: filename, line: newLine, title: "Possible GitHub token in code", body: "This added line looks like it may contain a GitHub access token. Remove it and rotate the token if it was real." });
      } else if (/\b(?:api[_-]?key|client[_-]?secret|password|access[_-]?token)\b\s*[:=]\s*["'][^"']{8,}["']/i.test(code)) {
        found.push({ path: filename, line: newLine, title: "Possible hard-coded credential", body: "This added line may contain a hard-coded credential. Move secrets to a secure environment variable and rotate the value if it was real." });
      } else if (/\beval\s*\(/.test(code)) {
        found.push({ path: filename, line: newLine, title: "Use of eval()", body: "Review this use of eval(): executing a string as code can introduce injection risks. Prefer parsing or a safer explicit operation." });
      }
      newLine++;
    } else if (line.startsWith(" ")) {
      newLine++;
    }
  }
  return found;
}

app.get("/", (_req, res) => res.status(200).send("Garuda PR review backend is running."));

app.post("/webhook", express.raw({ type: "application/json", limit: "2mb" }), async (req, res) => {
  if (!Buffer.isBuffer(req.body) || !verifySignature(req.body, req.get("x-hub-signature-256"))) {
    return res.sendStatus(401);
  }

  const event = req.get("x-github-event");
  const delivery = req.get("x-github-delivery");
  let payload;
  try {
    payload = JSON.parse(req.body.toString("utf8"));
  } catch {
    return res.status(400).send("Invalid JSON payload.");
  }

  if (event !== "pull_request" || !["opened", "reopened", "synchronize"].includes(payload.action)) {
    return res.sendStatus(202);
  }
  if (!process.env.GITHUB_APP_ID || !process.env.GITHUB_APP_PRIVATE_KEY || !payload.installation?.id) {
    console.error("GitHub App configuration is missing; delivery:", delivery);
    return res.sendStatus(500);
  }

  // Acknowledge quickly; GitHub retries deliveries that take too long.
  res.sendStatus(202);
  try {
    const privateKey = process.env.GITHUB_APP_PRIVATE_KEY.replace(/\\n/g, "\n");
    const octokit = new Octokit({
      authStrategy: createAppAuth,
      auth: { appId: process.env.GITHUB_APP_ID, privateKey, installationId: payload.installation.id }
    });
    const [owner, repo] = payload.repository.full_name.split("/");
    const prNumber = payload.pull_request.number;
    const headSha = payload.pull_request.head.sha;
    const { data: files } = await octokit.pulls.listFiles({ owner, repo, pull_number: prNumber, per_page: 100 });
    const findings = files.flatMap(file => scanPatch(file.filename, file.patch));

    await octokit.checks.create({
      owner, repo, name: "Garuda demo security scan", head_sha: headSha,
      status: "completed", conclusion: findings.length ? "failure" : "success",
      output: {
        title: findings.length ? `${findings.length} possible issue(s) found` : "No demo patterns found",
        summary: "This is a small demonstration scan for a few common patterns. It is not a full security audit."
      }
    });

    if (findings.length) {
      await octokit.pulls.createReview({
        owner, repo, pull_number: prNumber, event: "COMMENT",
        body: `Garuda's demo scan found ${findings.length} possible issue(s). Please verify each finding; these pattern checks can produce false positives.`,
        comments: findings.slice(0, 20).map(finding => ({
          path: finding.path, line: finding.line, side: "RIGHT",
          body: `**Garuda demo finding: ${finding.title}**\n\n${finding.body}`
        }))
      });
    }
    console.log(`Processed ${owner}/${repo}#${prNumber}: ${findings.length} finding(s); delivery ${delivery}`);
  } catch (error) {
    console.error("Garuda webhook processing failed; delivery:", delivery, error);
  }
});

app.listen(port, "0.0.0.0", () => console.log(`Garuda backend listening on port ${port}`));
