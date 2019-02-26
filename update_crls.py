#!/usr/bin/env python

from html.parser import HTMLParser
import json
from OpenSSL import crypto, SSL
import os
from pathlib import Path, PurePath
import pendulum
import requests
import re
import shutil
import tarfile

_DISA_CRL_INDEX = "https://iasecontent.disa.mil/pki-pke/data/crls/dod_crldps.htm"

_RACKSPACE_AUTH_URL = os.getenv("RACKSPACE_AUTH_URL")
_RACKSPACE_AUTH_USER = os.getenv("RACKSPACE_USERNAME")
_RACKSPACE_AUTH_SECRET = os.getenv("RACKSPACE_PASSWORD")

_STORAGE_BASE_URL = os.getenv("RACKSPACE_STORAGE_URL")
_STORAGE_CONTAINER_NAME = "crls"
_STORAGE_CRL_ARCHIVE_NAME = "dod_crls.tar.bz"


def rackspace_auth_request():
    payload = {'auth':{'RAX-KSKEY:apiKeyCredentials':{'username':_RACKSPACE_AUTH_USER,'apiKey':_RACKSPACE_AUTH_SECRET}}}

    try:
        response = requests.post(url=_RACKSPACE_AUTH_URL, json=payload)
    except requests.exceptions.RequestException:
        logger.error("unable to complete Rackspace auth request")

    if response.status_code != 200:
        logger.error("unable to authenticate with Rackspace (HTTP "+str(response.status_code)+" received)")
        exit()

    response_json = json.loads(response.text)
    return response_json

def rackspace_storage_archive_url(rackspace_account_id):
    return _STORAGE_BASE_URL+'/MossoCloudFS_'+rackspace_account_id+'/'+_STORAGE_CONTAINER_NAME+'/'+_STORAGE_CRL_ARCHIVE_NAME

def fetch_current_crls(current_crls_dir, crl_local_file):
    rackspace_auth_info = rackspace_auth_request()
    rackspace_account_id = rackspace_auth_info["access"]["token"]["tenant"]["id"]
    rackspace_token = rackspace_auth_info["access"]["token"]["id"]

    crl_archive_url = rackspace_storage_archive_url(rackspace_account_id)

    headers = {'X-Auth-Token': rackspace_token, 'Accept': 'application/json'}
    options = {"stream": True}

    logger.info("Downloading current CRL archive from {}".format(crl_archive_url))
    with requests.get(url=crl_archive_url, headers=headers, **options) as response:
        if response.status_code != 200:
            logger.error("unable to download CRL archive from {}".format(crl_archive_url)
                +" (HTTP "+str(response.status_code)+")")
            return False

        with open(crl_local_file, "wb") as crl_archive:
            for chunk in response.iter_content(chunk_size=1024):
                if chunk:
                    crl_archive.write(chunk)

    return True

def local_crl_archive_path(current_crls_dir):
    return current_crls_dir+'/'+_STORAGE_CRL_ARCHIVE_NAME

def populate_current_crls(current_crls_dir, logger):
    crl_local_archive_file = local_crl_archive_path(current_crls_dir)
    fetch_current_crls(current_crls_dir, crl_local_archive_file)
    logger.info("Unpacking current CRLs archive {}".format(crl_local_archive_file))
    crl_archive = tarfile.open(current_crls_dir+'/'+_STORAGE_CRL_ARCHIVE_NAME, 'r:bz2')
    crl_archive.extractall(current_crls_dir)
    crl_archive.close()
    os.remove(crl_local_archive_file)
    return True


def upload_updated_crls(current_crls_dir, logger):
    crl_local_archive_file = local_crl_archive_path(current_crls_dir)

    logger.info("Creating new CRL archive")
    with tarfile.open(crl_local_archive_file, "w:bz2") as tar:
        crl_dir = Path(current_crls_dir)
        crl_files = list(crl_dir.glob('*.crl'))
        for crl_file_path in crl_files[:]:
            logger.info("Adding {} to the archive...".format(crl_file_path))
            crl_file_name = PurePath(crl_file_path).name
            tar.add(crl_file_path, arcname=crl_file_name, recursive=False)

    rackspace_auth_info = rackspace_auth_request()
    rackspace_account_id = rackspace_auth_info["access"]["token"]["tenant"]["id"]
    rackspace_token = rackspace_auth_info["access"]["token"]["id"]

    crl_archive_url = rackspace_storage_archive_url(rackspace_account_id)

    headers = {'X-Auth-Token': rackspace_token, 'Accept': 'application/json'}
    options = {"stream": True}

    logger.info("Uploading new CRL archive")
    with open(crl_local_archive_file, "rb") as crl_archive:
       file_data = crl_archive.read()
       with requests.put(url=crl_archive_url, data=file_data, headers=headers, **options) as response:
          if response.status_code != 201:
              logger.error("unable to upload CRL archive to {}".format(crl_archive_url)
                  +" (HTTP "+str(response.status_code)+")")
              return False


def fetch_disa_crl_index(logger):
    try:
        response = requests.get(_DISA_CRL_INDEX)
    except requests.exceptions.RequestException:
            logger.error("unable to download CRL index (RequestException raised)")
    return response.text


# Checks if test_dir is in any way a subdirectory of the app's workspace
# (versus something potentially malicious, like '/some/appdir/../../etc')
def is_app_subdir(test_dir):
    app_dir = Path(os.path.realpath(sys.path[0]))
    test_dir = Path(test_dir)
    # Resolve symlink and any .. entries in the paths
    app_dir_resolved = app_dir.resolve()
    test_dir_resolved = test_dir.resolve(strict=False)
    # Test if test_dir is in any way a subdirectory of app_dir
    if app_dir_resolved in test_dir_resolved.parents:
        return True
    return False


class DISAParser(HTMLParser):
    _CRL_MATCH = re.compile("DOD(EMAIL|ID)?CA")

    def reset(self):
        self.crl_list = []
        HTMLParser.reset(self)

    def handle_starttag(self, tag, attrs):
        if tag == "a":
            href = [pair[1] for pair in attrs if pair[0] == "href"].pop()
            if re.search(self._CRL_MATCH, href):
                self.crl_list.append(href)


def crl_list_from_crl_index_html(html):
    parser = DISAParser()
    parser.reset()
    parser.feed(html)
    return parser.crl_list


def crl_local_path_from_url(temp_dir, crl_url):
    name = re.split("/", crl_url)[-1]
    crl = os.path.join(temp_dir, name)
    return crl


def existing_crl_modification_time(crl):
    if os.path.exists(crl):
        prev_time = os.path.getmtime(crl)
        dt = pendulum.from_timestamp(prev_time, tz="GMT")
        return dt.format("ddd, DD MMM YYYY HH:mm:ss zz")
    else:
        return False


def write_crl(temp_dir, current_crls_dir, crl_url, logger):
    crl = crl_local_path_from_url(temp_dir, crl_url)
    existing = crl_local_path_from_url(current_crls_dir, crl_url)
    options = {"stream": True}
    mod_time = existing_crl_modification_time(existing)
    if mod_time:
        options["headers"] = {"If-Modified-Since": mod_time}

    with requests.get(crl_url, **options) as response:
        if response.status_code == 304:
            logger.info("no changes for CRL from {}".format(crl_url))
            return False

        if response.status_code != 200:
            logger.error("unable to download CRL from {}".format(crl_url)
                +" (HTTP "+str(response.status_code)+")")
            return False

        # Capture the last-modified time from the response headers
        modified_time = pendulum.parse(response.headers['last-modified'],
                strict=False)
        with open(crl, "wb") as crl_file:
            for chunk in response.iter_content(chunk_size=1024):
                if chunk:
                    crl_file.write(chunk)

    # Set local file mod time to CRL's last-modified time
    os.utime(crl, (modified_time.int_timestamp, modified_time.int_timestamp))

    return True


def remove_bad_crl(temp_dir, crl_url):
    crl = crl_local_path_from_url(temp_dir, crl_url)
    if os.path.isfile(crl):
        os.remove(crl)


def fetch_crls(temp_dir, current_crls_dir, logger):
    crl_index_html = fetch_disa_crl_index(logger)
    crl_list = crl_list_from_crl_index_html(crl_index_html)
    for crl_url in crl_list:
        logger.info("Downloading CRL from {}".format(crl_url))
        try:
            write_crl(temp_dir, current_crls_dir, crl_url, logger)
        except requests.exceptions.RequestException:
            if logger:
                logger.error(
                    "Error downloading {}, removing file and continuing anyway".format(
                        crl_url
                    )
                )
            remove_bad_crl(temp_dir, crl_url)


def test_and_update_crls(temp_dir, current_crls_dir, logger):
    crl_dir = Path(temp_dir)
    crl_files = list(crl_dir.glob('*.crl'))
    for crl_file_path in crl_files[:]:
        with open(crl_file_path, 'rb') as crl_file:
            try:
                logger.info("Testing CRL file {}".format(crl_file_path))
                crypto.load_crl(crypto.FILETYPE_ASN1, crl_file.read())
                shutil.copy2(crl_file_path, current_crls_dir)
            except crypto.Error:
                logger.error("Could not load CRL file {}".format(crl_file_path)+"; Removing file...")
                if os.path.isfile(crl_file_path):
                    os.remove(crl_file_path)


if __name__ == "__main__":
    import logging
    import sys
    import time

    logging.basicConfig(
        level=logging.INFO, format="[%(asctime)s]:%(levelname)s: %(message)s"
    )
    logger = logging.getLogger()
    logger.info("Update CRLs Started")

    current_crls_dir = os.path.realpath(sys.path[0])+'/current'
    temp_dir = os.path.realpath(sys.path[0])+'/temp'

    # Guard against accidentally deleting key files by ensuring that the
    # current_crls_dir and temp_dir properly resolved to subdirectories of this
    # app
    if not is_app_subdir(current_crls_dir):
        logger.error("Derived temp_dir '{}' is not a subdirectory of this app's workspace".
                format(current_crls_dir)+"; Aborting...")
        exit()
    if not is_app_subdir(temp_dir):
        logger.error("Derived temp_dir '{}' is not a subdirectory of this app's workspace".
                format(temp_dir)+"; Aborting...")
        exit()

    while True:
        # Recreate the working directories, if it is safe to do so
        if shutil.rmtree.avoids_symlink_attacks:
            logger.info("Clearing local storage...")
            shutil.rmtree(current_crls_dir, ignore_errors=True)
            os.makedirs(current_crls_dir)
            shutil.rmtree(temp_dir, ignore_errors=True)
            os.makedirs(temp_dir)

        # Download and unpack the most recent CRLs archive
        populate_current_crls(current_crls_dir, logger)

        # Fetch updated versions of any CRLs that have changed
        try:
            fetch_crls(temp_dir, current_crls_dir, logger)
        except Exception as err:
            logger.exception("Fatal error encountered while fetching CRLs from DISA; stopping")
            sys.exit(1)

        # If there are any updated files...
        if os.listdir(temp_dir):
            # Test the new CRLs and then replace the old ones
            test_and_update_crls(temp_dir, current_crls_dir, logger)

            # Create and upload the new archive, overwriting the older one
            upload_updated_crls(current_crls_dir, logger)
        else:
            logger.info("No newer CRL files are available")

        logger.info("Finished updating CRLs")

        time.sleep(3600)
