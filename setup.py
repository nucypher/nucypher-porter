#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
from pathlib import Path
from typing import Dict

from setuptools import find_packages, setup
from setuptools.command.develop import develop
from setuptools.command.install import install

#
# Metadata
#

PACKAGE_NAME = 'porter'
BASE_DIR = Path(__file__).parent
PYPI_CLASSIFIERS = [
    "Development Status :: 3 - Alpha",
    "Intended Audience :: Developers",
    "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)"
    "Natural Language :: English",
    "Operating System :: OS Independent",
    "Programming Language :: Python",
    "Programming Language :: Python :: 3 :: Only",
    "Programming Language :: Python :: 3.10",
    "Programming Language :: Python :: 3.11",
    "Programming Language :: Python :: 3.12",
    "Programming Language :: Python :: 3.13",
    "Topic :: Security",
]

ABOUT: Dict[str, str] = dict()
SOURCE_METADATA_PATH = BASE_DIR / PACKAGE_NAME / "__about__.py"
with open(str(SOURCE_METADATA_PATH.resolve())) as f:
    exec(f.read(), ABOUT)


#
# Utilities
#

class VerifyVersionCommand(install):
    """Custom command to verify that the git tag matches our version"""
    description = 'verify that the git tag matches our version'

    def run(self):
        tag = os.getenv('CIRCLE_TAG')
        if tag.startswith('v'):
            tag = tag[1:]

        version = ABOUT['__version__']
        if version.startswith('v'):
            version = version[1:]

        if tag != version:
            info = "Git tag: {0} does not match the version of this app: {1}".format(
                os.getenv('CIRCLE_TAG'), ABOUT['__version__']
            )
            sys.exit(info)


class PostDevelopCommand(develop):
    """
    Post-installation for development mode.
    Execute manually with python setup.py develop or automatically included with
    `pip install -e . -r dev-requirements.txt`.
    """
    def run(self):
        """development setup scripts (pre-requirements)"""
        develop.run(self)


#
#  Requirements
#


def read_requirements(path):
    with open(BASE_DIR / path) as f:
        return f.read().split("\n")


INSTALL_REQUIRES = read_requirements('requirements.txt')
DEV_REQUIRES = read_requirements('dev-requirements.txt')

DEPLOY_REQUIRES = [
    'bumpversion',
    'twine',
    'wheel'
]

EXTRAS = {
    'dev': DEV_REQUIRES,
    'deploy': DEPLOY_REQUIRES
}

# read the contents of the README file
long_description = (BASE_DIR / "README.rst").read_text()

setup(

    # Requirements
    python_requires=">=3.10,<4",
    install_requires=INSTALL_REQUIRES,
    extras_require=EXTRAS,

    # Package Data
    packages=find_packages(exclude=["tests", "scripts"]),
    include_package_data=True,
    zip_safe=False,

    # Entry Points
    entry_points={'console_scripts': [
      'nucypher-porter = porter.cli.main:porter_cli',
    ]},

    # setup.py commands
    cmdclass={
        'verify': VerifyVersionCommand,
        'develop': PostDevelopCommand
    },

    # Metadata
    name=ABOUT['__title__'],
    url=ABOUT['__url__'],
    version=ABOUT['__version__'],
    author=ABOUT['__author__'],
    author_email=ABOUT['__email__'],
    description=ABOUT['__summary__'],
    license=ABOUT['__license__'],
    long_description_content_type="text/x-rst",
    long_description=long_description,
    keywords="porter",
    classifiers=PYPI_CLASSIFIERS,
)
