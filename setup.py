from setuptools import setup, find_packages

setup(
    name="certbot-dns-dnscale",
    version="1.0.0",
    description="DNScale DNS Authenticator plugin for certbot",
    url="https://github.com/dnscaleou/certbot-dns-dnscale",
    author="DNScale",
    author_email="ops@dnscale.eu",
    license="Apache License 2.0",
    python_requires=">=3.8",
    packages=find_packages(),
    install_requires=[
        "certbot>=2.0.0",
        "requests>=2.25.0",
    ],
    entry_points={
        "certbot.plugins": [
            "dns-dnscale = certbot_dns_dnscale.dns_dnscale:Authenticator",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Environment :: Plugins",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Topic :: Internet :: Name Service (DNS)",
        "Topic :: Security",
        "Topic :: System :: Systems Administration",
    ],
)
