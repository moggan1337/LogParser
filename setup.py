from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="logparser",
    version="1.0.0",
    author="LogParser Team",
    author_email="team@logparser.dev",
    description="Advanced log parsing and analysis engine",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/moggan1337/LogParser",
    packages=find_packages(exclude=["tests", "tests.*", "examples", "benchmarks"]),
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: System :: Logging",
        "Topic :: Software Development :: Libraries :: Python Modules",
    ],
    python_requires=">=3.8",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=4.0.0",
            "black>=23.0.0",
            "flake8>=6.0.0",
            "mypy>=1.0.0",
        ],
        "pandas": [
            "pandas>=2.0.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "logparser=logparser.cli:main",
        ],
    },
    include_package_data=True,
    zip_safe=False,
)
