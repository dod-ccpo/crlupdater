# crlupdater

[![Build Status](https://circleci.com/gh/dod-ccpo/crlupdater.svg?style=svg)](https://circleci.com/gh/dod-ccpo/crlupdater)

## Description

This is a Python script for keeping our CRL archive up-to-date

## Installation

### System Requirements
* `python` == 3.6
  Python version 3.6 must be installed on your machine before installing `pipenv`.
  You can download Python 3.6 [from python.org](https://www.python.org/downloads/)
  or use your preferred system package manager.

* `pipenv`
  ATST requires `pipenv` to be installed for python dependency management. `pipenv`
  will create the virtual environment that the app requires. [See
  `pipenv`'s documentation for instructions on installing `pipenv](
  https://pipenv.readthedocs.io/en/latest/install/#installing-pipenv).

### Cloning
This project contains git submodules. Here is an example clone command that will
automatically initialize and update those modules:

    git clone --recurse-submodules git@github.com:dod-ccpo/atst.git

If you have an existing clone that does not yet contain the submodules, you can
set them up with the following command:

    git submodule update --init --recursive

### Setup
This application uses Pipenv to manage Python dependencies and a virtual
environment. Instead of the classic `requirements.txt` file, pipenv uses a
Pipfile and Pipfile.lock, making it more similar to other modern package managers
like yarn or mix.

To perform the create the virtual environment and install dependencies, run:

    pipenv install


To enter the virtualenv manually (a la `source .venv/bin/activate`):

    pipenv shell

If you want to automatically load the virtual environment whenever you enter the
project directory, take a look at [direnv](https://direnv.net/).  An `.envrc`
file is included in this repository.  direnv will activate and deactivate
virtualenvs for you when you enter and leave the directory.
