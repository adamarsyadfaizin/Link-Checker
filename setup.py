from setuptools import find_packages, setup

setup(
    name="link-check",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        "requests",
        "python-whois",
        "tldextract",
        "colorama",
        "python-Levenshtein",
    ],
    entry_points={
        "console_scripts": [
            "link-check=link_check.main:main",
        ],
    },
    python_requires=">=3.8",
)
