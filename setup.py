from setuptools import setup

setup(
    name='py-plesk-domains',
    version='1.1.0',
    scripts=['py_plesk_domains.py'],
    entry_points={
        'console_scripts': [
            'py-plesk-domains=py_plesk_domains:main',
        ]
    },
    install_requires=[
        'tabulate',
        'pyOpenSSL',
        'requests'
    ]
)