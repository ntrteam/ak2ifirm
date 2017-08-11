#!/usr/bin/env python
from setuptools import setup
import os

def read(fname):
     return open(os.path.join(os.path.dirname(__file__), fname)).read()

setup(
    name='ak2ifirm',
    version='1.0',
    author='Sunguk Lee',
    author_email='d3m3vilurr@gmail.com',
    description='Inject boot9strap firm for AK2I flashcart',
    license='GPLv3',
    long_description=read('README.md'),
    packages=['ak2ifirm'],
    install_requires=['PyCRC'],
    entry_points={ "console_scripts": [ "ak2ifirm=ak2ifirm:main" ]},
    classifiers=[
        "Topic :: Utilities",
        "License :: OSI Approved :: GNU General Public License v3 (GPLv3)",
    ]
)
