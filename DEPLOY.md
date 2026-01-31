# 🚀 Project Atlas - Deployment Guide

This guide walks you through deploying Project Atlas to production using **Railway** (recommended) with a GitHub Actions CI/CD pipeline.

---

## 📋 Table of Contents

1. [Prerequisites](#prerequisites)
2. [Quick Start (5 minutes)](#quick-start)
3. [Detailed Railway Setup](#detailed-railway-setup)
4. [CI/CD Pipeline Setup](#cicd-pipeline-setup)
5. [Custom Domain Setup](#custom-domain-setup)
6. [Environment Variables](#environment-variables)
7. [Alternative Platforms](#alternative-platforms)
8. [Troubleshooting](#troubleshooting)

---

## Prerequisites

Before deploying, ensure you have:

- [ ] **GitHub Account** with your code pushed to a repository
- [ ] **OpenAI API Key** (or other LLM provider credentials)
- [ ] **Railway Account** ([Sign up free](https://railway.app))

---

## Quick Start

### 1. Push to GitHub (if not already done)

```bash
git init
git add .
git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/Project-Atlas.git
git push -u origin main
```

### 2. Deploy to Railway

1. Go to [railway.app](https://railway.app) and sign in with GitHub
2. Click **"New Project"** → **"Deploy from GitHub repo"**
3. Select your `Project-Atlas` repository
4. Railway will auto-detect the Dockerfile and start building

### 3. Configure Environment Variables

In Railway dashboard → Your project → **Variables** tab, add:

```
LLM_PROVIDER=openai
LLM_MODEL=gpt-4o
OPENAI_API_KEY=sk-your-key-here
```

### 4. Access Your App

Railway will provide a URL like: `https://project-atlas-production.up.railway.app`

**That's it! Your app is live! 🎉**

---

## Detailed Railway Setup

### Step 1: Create Railway Account

1. Visit [railway.app](https://railway.app)
2. Click **"Login"** → **"Login with GitHub"**
3. Authorize Railway to access your repositories

### Step 2: Create New Project

1. From Railway dashboard, click **"New Project"**
2. Select **"Deploy from GitHub repo"**
3. Choose `Project-Atlas` from the repository list
4. Railway will:
   - Clone your repository
   - Detect the `Dockerfile`
   - Build the Docker image
   - Deploy the container

### Step 3: Configure Settings

#### Variables (Required)

Navigate to your project → Click the service → **Variables** tab:

| Variable | Value | Required |
|----------|-------|----------|
| `LLM_PROVIDER` | `openai` | ✅ |
| `OPENAI_API_KEY` | `sk-your-api-key` | ✅ |
| `LLM_MODEL` | `gpt-4o` | ✅ |
| `VIRUSTOTAL_API_KEY` | Your VT key | ❌ |

#### Networking

1. Go to **Settings** → **Networking**
2. Click **"Generate Domain"** to get a public URL
3. Or configure a custom domain (see below)

#### Persistent Storage (Recommended)

To persist scan results and database:

1. Go to **Settings** → **Volumes**
2. Add volume mount: `/app/data` → `project-atlas-data`
3. Add volume mount: `/app/extensions_storage` → `extensions-storage`

### Step 4: Verify Deployment

1. Click the generated URL (e.g., `project-atlas-xxx.up.railway.app`)
2. You should see the Project Atlas frontend
3. Test the API at `/docs` for Swagger documentation
4. Check health endpoint at `/health`

---

## CI/CD Pipeline Setup

The repository includes a GitHub Actions workflow (`.github/workflows/deploy.yml`) that automatically:

1. **Runs tests** on every push
2. **Builds Docker image** and pushes to GitHub Container Registry
3. **Deploys to Railway** on push to `main` branch

### Enable the Pipeline

#### 1. Get Railway Token

1. Go to [railway.app/account/tokens](https://railway.app/account/tokens)
2. Click **"Create Token"**
3. Name it `github-actions`
4. Copy the token

#### 2. Add GitHub Secret

1. Go to your GitHub repo → **Settings** → **Secrets and variables** → **Actions**
2. Click **"New repository secret"**
3. Name: `RAILWAY_TOKEN`
4. Value: Paste the Railway token
5. Click **"Add secret"**

#### 3. Link Railway Project

Get your Railway project ID:

1. In Railway dashboard, click your project
2. Go to **Settings** → **General**
3. Copy the **Project ID**

Create a `railway.json` in your repo root (if not using project linking):

```json
{
  "projectId": "your-project-id-here"
}
```

### Pipeline Workflow

After setup, the pipeline works automatically:

```
Push to main → Tests Run → Docker Build → Deploy to Railway
                ↓              ↓                ↓
           (2 min)        (5 min)          (2 min)
```

Every push to `main` will deploy automatically! 🚀

---

## Custom Domain Setup

### Option 1: Railway Subdomain (Free)

Railway provides free subdomains like `project-atlas-xxx.up.railway.app`

### Option 2: Custom Domain (Recommended for Production)

1. **In Railway:**
   - Go to project → **Settings** → **Networking**
   - Click **"Custom Domain"**
   - Enter your domain: `atlas.yourdomain.com`
   - Railway will show DNS records

2. **In Your DNS Provider (GoDaddy, Cloudflare, etc.):**
   - Add a CNAME record:
     ```
     Type: CNAME
     Name: atlas (or @ for root domain)
     Value: <railway-cname-target>
     TTL: Auto
     ```

3. **Wait for DNS propagation** (5 min - 48 hours)

4. **Update Environment Variable:**
   ```
   CUSTOM_DOMAIN=atlas.yourdomain.com
   ```

---

## Environment Variables

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `LLM_PROVIDER` | AI provider | `openai`, `watsonx`, `ollama` |
| `OPENAI_API_KEY` | OpenAI API key | `sk-...` |
| `LLM_MODEL` | Model name | `gpt-4o`, `gpt-4-turbo` |

### Optional Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `VIRUSTOTAL_API_KEY` | VirusTotal integration | (none) |
| `CUSTOM_DOMAIN` | Your custom domain | (none) |
| `CORS_ORIGINS` | Comma-separated allowed origins | Auto-detected |
| `PORT` | Server port | `8007` |

### Setting Variables in Railway

```bash
# Via Railway CLI
railway variables set OPENAI_API_KEY=sk-your-key

# Or in dashboard: Project → Variables → Add Variable
```

---

## Alternative Platforms

### Render

1. Create account at [render.com](https://render.com)
2. New → Web Service → Connect GitHub
3. Select repository
4. Render auto-detects Dockerfile
5. Add environment variables
6. Deploy!

**render.yaml** (optional - add to repo):
```yaml
services:
  - type: web
    name: project-atlas
    runtime: docker
    dockerfilePath: ./Dockerfile
    envVars:
      - key: LLM_PROVIDER
        value: openai
      - key: OPENAI_API_KEY
        sync: false  # Set manually
```

### Fly.io

```bash
# Install Fly CLI
curl -L https://fly.io/install.sh | sh

# Login
fly auth login

# Launch (first time)
fly launch --name project-atlas

# Set secrets
fly secrets set OPENAI_API_KEY=sk-your-key

# Deploy
fly deploy
```

### DigitalOcean App Platform

1. Go to [cloud.digitalocean.com/apps](https://cloud.digitalocean.com/apps)
2. Create App → GitHub
3. Select repository
4. Configure as Web Service
5. Add environment variables
6. Deploy!

---

## Troubleshooting

### Build Fails

**Issue:** Docker build fails with npm errors

**Solution:** Ensure `frontend/package-lock.json` is committed:
```bash
cd frontend
npm install
git add package-lock.json
git commit -m "Add package-lock.json"
```

### Container Crashes

**Issue:** Container starts but immediately crashes

**Check logs:**
```bash
railway logs
```

**Common fixes:**
- Ensure `OPENAI_API_KEY` is set correctly
- Check for missing environment variables
- Verify port is `8007`

### 502 Bad Gateway

**Issue:** App deployed but shows 502 error

**Solutions:**
1. Wait 2-3 minutes for container to fully start
2. Check if health check passes: `/health`
3. Ensure port matches: `PORT=8007`

### CORS Errors

**Issue:** Frontend can't reach API

**Solution:** Set custom CORS origins:
```
CORS_ORIGINS=https://your-frontend-domain.com,https://your-app.up.railway.app
```

### Database Persistence

**Issue:** Scan results disappear after redeploy

**Solution:** Add persistent volume in Railway:
1. Project → Settings → Volumes
2. Mount `/app/data`

---

## Monitoring & Logs

### Railway Dashboard

- Real-time logs in the **Deployments** tab
- CPU/Memory metrics in **Metrics** tab
- Deployment history and rollback options

### CLI Monitoring

```bash
# Install Railway CLI
npm install -g @railway/cli

# Login
railway login

# Link project
railway link

# View logs
railway logs

# SSH into container
railway shell
```

---

## Cost Estimation

| Platform | Free Tier | Typical Cost |
|----------|-----------|--------------|
| Railway | $5 credit/month | $5-20/month |
| Render | 750 hours free | $7/month |
| Fly.io | 3 shared VMs free | $5-15/month |
| DigitalOcean | None | $12/month |

**Note:** LLM API costs (OpenAI) are separate and depend on usage.

---

## Quick Reference

```bash
# Local development
make docker-build
make docker-up

# Deploy to Railway (CLI)
railway login
railway link
railway up

# View production logs
railway logs

# Run production locally
docker compose up
```

---

## Need Help?

- 📖 [Railway Documentation](https://docs.railway.app)
- 💬 [Railway Discord](https://discord.gg/railway)
- 🐛 [Project Atlas Issues](https://github.com/YOUR_USERNAME/Project-Atlas/issues)


