# Garuda PR review backend (demo)

This small Node.js service receives GitHub App pull-request webhooks, scans added lines for three demonstration patterns (token-like strings, hard-coded credentials, and `eval()`), creates a GitHub Check, and posts inline review comments when it finds matches.

This is a learning prototype, not a complete security scanner. Pattern matching can miss issues and produce false positives. Test only on the intended repository. The app responds to pull requests opened, reopened, or updated with new commits.

## Required GitHub App setup

- Repository permissions: Contents **read**, Pull requests **read and write**, Checks **read and write**.
- Subscribe to the **Pull request** webhook event.
- Install the app only on `abed-cseu1550/garuda-prototype` for this test.
- Keep the app private. Never commit the private key or webhook secret.

## Deploy on Render

Copy these files into a `backend` folder in the Garuda repository. Connect that repository to a Render **Web Service**, set the service root directory to `backend`, build command to `npm install`, and start command to `npm start`. Select the Free plan for a demo. Free services can sleep when idle and may take about a minute to wake.

After deploy, the webhook URL is `https://YOUR-SERVICE.onrender.com/webhook`.

In Render environment variables, set:

- `GITHUB_APP_ID`: the numeric App ID from the GitHub App settings.
- `GITHUB_APP_PRIVATE_KEY`: the full PEM private key contents. Store only in Render, never in GitHub or chat.
- `GITHUB_WEBHOOK_SECRET`: a long random secret. Use the same value in the GitHub App Webhook secret field.

Then enable the app webhook in GitHub App settings, paste the Render webhook URL, enter the matching webhook secret, and subscribe to **Pull request** events. Save. Install the app on the test repository if you have not already done so.

## Local run

Requires Node.js 20 or newer. In this folder, run `npm install` and then `npm start`. Configure the three environment variables before starting. A local server is not reachable by GitHub unless you also use a secure public webhook tunnel; deploying to Render is simpler for this demo.
