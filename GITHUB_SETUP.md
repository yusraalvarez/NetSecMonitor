# GitHub Setup Guide for NetSecMonitor

This guide will walk you through uploading this project to GitHub, even if you've never used Git before.

## Step 1: Install Git (if not already installed)

On macOS, Git is usually pre-installed. Check by opening Terminal and typing:
```bash
git --version
```

If you get a version number, you're good to go. If not, install Git:
```bash
# On macOS, run:
xcode-select --install
```

## Step 2: Configure Git (First Time Only)

Set your name and email (this will be public on GitHub):
```bash
git config --global user.name "Your Name"
git config --global user.email "your.email@example.com"
```

## Step 3: Create a GitHub Account

1. Go to https://github.com
2. Click "Sign up"
3. Follow the instructions to create your account

## Step 4: Create a New Repository on GitHub

1. Log in to GitHub
2. Click the "+" icon in the top right corner
3. Select "New repository"
4. Repository name: `NetSecMonitor`
5. Description: "Network Security Monitoring and Analysis Tool"
6. Select "Public" (so employers can see it)
7. **Do NOT** check "Initialize with README" (we already have one)
8. Click "Create repository"

## Step 5: Upload Your Project to GitHub

Open Terminal and navigate to your project directory:
```bash
cd /path/to/NetSecMonitor
```

Then run these commands **ONE AT A TIME**:

### Initialize Git repository
```bash
git init
```

### Add all files to git
```bash
git add .
```

### Create your first commit
```bash
git commit -m "Initial commit: NetSecMonitor project"
```

### Add your GitHub repository as remote
**IMPORTANT**: Replace `YOUR-USERNAME` with your actual GitHub username:
```bash
git remote add origin https://github.com/YOUR-USERNAME/NetSecMonitor.git
```

### Rename branch to main (if needed)
```bash
git branch -M main
```

### Push your code to GitHub
```bash
git push -u origin main
```

You'll be prompted for your GitHub username and password. 

**Note**: GitHub now requires a Personal Access Token instead of password. To create one:
1. Go to GitHub → Settings → Developer settings → Personal access tokens → Tokens (classic)
2. Click "Generate new token (classic)"
3. Give it a name like "Git Access"
4. Select scopes: Check "repo" (this gives full control of private repositories)
5. Click "Generate token"
6. **COPY THE TOKEN** - you won't see it again!
7. Use this token as your password when pushing

## Step 6: Verify Upload

Go to `https://github.com/YOUR-USERNAME/NetSecMonitor` in your browser. You should see all your files!

## Step 7: Make Your Repository Look Professional

### Add Topics (Tags)
1. On your GitHub repository page, click the gear icon next to "About"
2. Add topics: `python`, `security`, `networking`, `monitoring`, `cybersecurity`, `devops`, `sre`, `data-engineering`
3. Add website if you deploy it
4. Click "Save changes"

### Pin the Repository
1. Go to your GitHub profile page
2. Click "Customize your pins"
3. Select NetSecMonitor
4. Click "Save pins"

This makes it appear prominently on your profile!

## Common Git Commands You'll Need

### Make changes to your code and update GitHub:
```bash
# Check what files changed
git status

# Add all changed files
git add .

# Commit with a message describing what you changed
git commit -m "Added new feature X"

# Push to GitHub
git push
```

### Create a new feature branch:
```bash
# Create and switch to new branch
git checkout -b feature-name

# When done, push the branch
git push -u origin feature-name

# Then create a Pull Request on GitHub
```

## Troubleshooting

### Error: "remote origin already exists"
```bash
git remote remove origin
git remote add origin https://github.com/YOUR-USERNAME/NetSecMonitor.git
```

### Error: "fatal: not a git repository"
Make sure you're in the project directory and run `git init` first.

### Error: Authentication failed
Make sure you're using a Personal Access Token, not your GitHub password.

### Want to start over?
```bash
# Remove git tracking
rm -rf .git

# Start fresh
git init
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/YOUR-USERNAME/NetSecMonitor.git
git push -u origin main
```

## Making Your Repository Stand Out

### 1. Add Screenshots
Create a `screenshots/` directory and add images of:
- Your dashboard in action
- Sample security alerts
- Port scan results

Then add them to your README:
```markdown
![Dashboard Screenshot](screenshots/dashboard.png)
```

### 2. Add a LICENSE file
On GitHub, click "Add file" → "Create new file"
Name it `LICENSE` and select "Choose a license template"
We recommend MIT License for portfolio projects.

### 3. Enable GitHub Pages (if you want a project website)
1. Go to repository Settings
2. Scroll to "Pages"
3. Source: Deploy from a branch
4. Branch: main, folder: / (root)
5. Save

### 4. Add a badge to your README
```markdown
![Python](https://img.shields.io/badge/python-3.8+-blue.svg)
![License](https://img.shields.io/badge/license-MIT-green.svg)
```

## Next Steps

1. ✅ Push your code to GitHub
2. ✅ Add the repository to your resume and LinkedIn
3. ✅ Share the link when applying to jobs
4. ✅ Continue adding features and updating the repository
5. ✅ Write a blog post about what you built and link to the repo

## Your GitHub URL

Your project will be at:
```
https://github.com/YOUR-USERNAME/NetSecMonitor
```

**Add this URL to:**
- Your resume (in the projects section)
- Your LinkedIn (in the projects section)
- Job applications (when they ask for portfolio)

---

**Questions?** 
- Git documentation: https://git-scm.com/doc
- GitHub guides: https://guides.github.com
- Stack Overflow for specific issues
