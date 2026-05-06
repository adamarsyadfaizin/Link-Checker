# Link Check

Simple cyber-style terminal URL risk analyzer.

By Adam: https://github.com/adamarsyadfaizin

## Quick Run

```powershell
python run.py
```

You will get a colored terminal menu. Choose:

```text
1. Link checker
0. Exit
```

Inside link checker mode:

```text
check https://google.com
explain https://goggle.com
scantext
back
exit
```

`check` automatically tries to inspect supported shared-page APIs such as
`claude.ai/api/share/<id>` so social-engineering content can be detected from the URL.
It also checks the full URL path/query for threat terms such as `phishing`,
`malware`, and `credential`, plus known Google Safe Browsing test URLs.
For `scantext`, paste suspicious local content and type `END` on a new line.

## Direct CLI

```powershell
python -m link_check.main https://google.com
python -m link_check.main explain https://goggle.com
```

After local install:

```powershell
pip install .
link-check https://google.com
```
