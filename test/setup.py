from setuptools import setup, find_packages

setup(
    name='network-threat-intelligence-scanner',
    version='0.1',
    packages=find_packages(),
    install_requires=[
        'requests',
    ],
    entry_points={
        'console_scripts': [
            'network-threat-intelligence-scanner=src.main:main',
        ],
    },
)
