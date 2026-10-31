from setuptools import setup, find_packages

setup(
    name="profipwn",
    version="1.0.0",
    description="First Offensive Security Framework for PROFINET Industrial Ethernet",
    packages=find_packages(),
    python_requires=">=3.8",
    install_requires=[],
    extras_require={"scapy": ["scapy>=2.5.0"]},
    entry_points={
        "console_scripts": [
            "profipwn=profipwn.cli:main",
        ],
    },
)
