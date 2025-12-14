# MonaLeak 🔍

**API Discovery and Sensitive Data Scanner Tool**

MonaLeak is a powerful OSINT tool that discovers APIs from various sources and detects sensitive data (API keys, tokens, passwords, etc.).

---

## 📦 Installation

```bash
pip install -r requirements.txt
```


---

## 🚀 Usage

```bash
███╗   ███╗ ██████╗ ███╗   ██╗ █████╗ ██╗     ███████╗ █████╗ ██╗  ██╗
████╗ ████║██╔═══██╗████╗  ██║██╔══██╗██║     ██╔════╝██╔══██╗██║ ██╔╝
██╔████╔██║██║   ██║██╔██╗ ██║███████║██║     █████╗  ███████║█████╔╝ 
██║╚██╔╝██║██║   ██║██║╚██╗██║██╔══██║██║     ██╔══╝  ██╔══██║██╔═██╗ 
██║ ╚═╝ ██║╚██████╔╝██║ ╚████║██║  ██║███████╗███████╗██║  ██║██║  ██╗
╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝




Usage: python3 monaleak.py <parameter> <search_term>
Parameters:
  -s : Search only SwaggerHub                                                                                                                                                                                                                                               
  -p : Search only Postman                                                                                                                                                                                                                                                  
  -g : Perform Dork search                                                                                                                                                                                                                                                  
  -gh : Perform GitHub search                                                                                                                                                                                                                                               
  -a : Search all                                                                                                                                                                                                                                                           
  -e/-explore : Find all secret in URLS    
```


---

## ⚙️ Configuration

### GitHub Token (Optional)
To use the GitHub search feature, set the `GITHUB_TOKEN` variable:



---


## ⚠️ Legal Disclaimer

This tool should only be used for legal and ethical purposes:
- Security testing of your own systems
- Authorized testing within bug bounty programs
- Security research




