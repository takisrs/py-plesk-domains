from setuptools import setup

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name='py-plesk-domains',
    version='1.1.1',
    author="Panagiotis Pantazopoulos",
    author_email="takispadaz@gmail.com",
    description="Get some basic data about domains from a server with plesk panel",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/takisrs/py-plesk-domains",
    scripts=['py_plesk_domains.py'],
    entry_points={
        'console_scripts': [
            'py-plesk-domains=py_plesk_domains:main',
        ]
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    install_requires=[
        'tabulate',
        'pyOpenSSL',
        'requests'
    ]
)