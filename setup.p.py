from setuptools import setup, find_packages

setup(
    name="SystemInfoCollector",
    version="1.0.0",
    description="System Information Collector with GUI",
    author="Your Name",
    packages=find_packages(),
    install_requires=[
        "psutil>=5.9.0",
    ],
    python_requires=">=3.6",
    entry_points={
        'console_scripts': [
            'system-info-collector=system_info_gui:main',
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: MIT License",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX :: Linux",
        "Operating System :: MacOS",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
)