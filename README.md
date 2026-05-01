# ⚡ SysAdmin PowerShell Script Bank

A searchable, categorized reference of 693+ PowerShell scripts for IT professionals — covering Active Directory, Entra ID, Exchange Online, Intune, Microsoft Defender, Purview, SharePoint Online, M365, Azure, Network Troubleshooting, Windows Server, and Automation.

## 🚀 Live Site
**[kidlearning99.github.io/sysadmin-script-bank](https://kidlearning99.github.io/sysadmin-script-bank)**

## 📂 Categories
| Category | Scripts |
|---|---|
| Active Directory | 101 |
| Entra ID | 82 |
| Exchange Online | 83 |
| Intune | 51 |
| Microsoft Defender | 53 |
| Microsoft Purview | 45 |
| SharePoint Online | 52 |
| M365 / General | 46 |
| Network Troubleshooting | 51 |
| Windows Server | 50 |
| Automation | 39 |
| Azure | 40 |

## ✨ Features
- **Search** across all script titles, descriptions, and code
- **Filter** by category using the tab bar
- **Copy** any script to clipboard in one click
- **Add** your own custom scripts (saved locally in your browser)
- **Syntax highlighting** for PowerShell cmdlets, parameters, and strings

## 🛠️ How to Deploy to GitHub Pages

1. Fork or clone this repo
2. Go to **Settings → Pages**
3. Set Source to **Deploy from a branch → main → / (root)**
4. Your site will be live at `https://kidlearning99.github.io/sysadmin-script-bank`

## ➕ Adding Scripts (Pull Request)
To add scripts to the permanent list (visible to everyone):
1. Edit `scripts-data.js`
2. Add entries following the existing format:
```js
{"cat":"ad","title":"My Script Title","desc":"What it does","code":"Your-PowerShell -Code here"},
```
3. Submit a Pull Request

## ⚠️ Disclaimer
Always test scripts in a dev/lab environment before running in production. The wipe, revoke, delete, and lock commands are irreversible.

---
*Maintained by kidlearning99 · Built with HTML/CSS/JavaScript*
