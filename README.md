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

For `scantext`, paste suspicious content and type `END` on a new line.

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
