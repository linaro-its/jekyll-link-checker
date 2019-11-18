#!/usr/bin/python3
#

import sys
import os
from os.path import join
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import argparse
import socket
import aiohttp
import asyncio
import concurrent
from link_db import LinkCheckerDB

# The link checking process depends on whether it is a relative
# or absolute link. If it is a relative link, a file is looked for
# that matches the relative path.
#
# If it is an absolute link, the pair of filename and link are stored,
# along with a list of unique links to be checked. At the end of the
# scan, all of the unique links are checked in an async process and
# the results stored. Those results are then used to update the list
# of filename/link pairs.


class JekyllLinkChecker:
    def __init__(self):
        self.CHROME = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/41.0.2228.0 Safari/537.36'
        }
        self.file_link_pairs = []
        self.unique_links = []
        self.failed_links = []
        self.unique_links = []
        self.skip_elements = {
            "a": "#edit_on_github"
        }
        self.status_count = 0
        self.html_cache_results = {}
        self.dns_skip = []
        self.verbose = 0
        self.output_file = None
        self.args = self.parse_args()
        if self.args.db:
            # Create a new instance of the LinkCheckerDB object
            if self.args.db_file:
                self.sqlite_database = LinkCheckerDB()
            else:
                self.sqlite_database = LinkCheckerDB(self.args.db_file)
        else:
            self.sqlite_database = None
        self.main()

    def main(self):
        """
        Main method - runs on instantiation
        """
        print("Linaro Link Checker")
        if self.args.verbose is not None:
            self.verbose = self.args.verbose
            print("Verbosity is at level %s" % self.verbose)
        if self.args.skip_dns_check is not None:
            print("Loading FQDN skip list from %s" % self.args.skip_dns_check)
            try:
                self.dns_skip = list(open(self.args.skip_dns_check))
            except Exception as exception:
                print("Couldn't load FQDN skip list:", exception)
        if self.args.output is not None:
            self.output_file = self.args.output
        if self.args.directory is not None:
            print("Scanning '%s'" % self.args.directory)
            os.chdir(self.args.directory)
        if self.args.nointernal:
            print("Skipping internal link checking")
        if self.args.noexternal:
            print("Skipping external link checking")
        # For now, assume that we're just scanning the current directory. Add code
        # for file paths and possibly URLs at a future date ...
        self.scan_directory("./", self.args.skip_path)

    def parse_args(self):
        parser = argparse.ArgumentParser(
            description="Scan for broken links")
        parser.add_argument('-d', '--directory', nargs='?', default=None,
                            help='specifies the directory to scan')
        parser.add_argument('--skip-dns-check', nargs='?', default=None,
                            help='specifies text file of FQDNs to skip the DNS '
                            'check on')
        parser.add_argument('-s', '--skip-path', action='append',
                            help='specifies a path to skip when checking URLs', default=None)
        parser.add_argument('-v', '--verbose', action='count')
        parser.add_argument('-f', '--file', action='append',
                            help=('specifies a file to check;'
                                  ' all non-specified files are ignored'))
        parser.add_argument('--nointernal', action='store_true',
                            help='skips checking of internal references')
        parser.add_argument('--noexternal', action='store_true',
                            help='skips checking of external references')
        parser.add_argument('--db', action='store_true',
                            help='Use a sqlite db to cache results', default=False)
        parser.add_argument('--db_file', action='store_true',
                            help='Specify the path to an existing sqlite database', default=None)
        parser.add_argument('-o', '--output', nargs='?', default=None,
                            help='specifies output file for error results')
        parser.add_argument('--no-external-errors', action='store_true',
                            help='ignores errors caused by external broken links')
        return parser.parse_args()

    def drop_dot(self, foo):
        if foo != "" and foo[0] == '.':
            return foo[1:]
        return foo

    def get_all_html_files(self, path):
        result = []
        for root, dirs, files in os.walk(path):
            for name in files:
                if name.endswith((".html", ".htm")):
                    f = os.path.join(root, name)
                    if f not in result:
                        if self.verbose >= 3:
                            print("File scan: adding '%s'" % f)
                        result.append(f)
            for d in dirs:
                files_in_d = self.get_all_html_files(join(root, d))
                if files_in_d:
                    for f in files_in_d:
                        if f not in result:
                            if self.verbose >= 3:
                                print("File scan: adding '%s'" % f)
                            result.append(f)
        return result

    def validate_file_link(self, filename, text):
        # If there is an anchor (#) in the text, we need to look at what
        # comes before it.
        text = text.split("#")[0]
        # If there is a query (?) in the text, we need to look at what
        # comes before it.
        text = text.split("?")[0]
        # If "text" starts with "/" then we need to be looking at the
        # path relative to where we started scanning.
        #
        # Otherwise, it will be relative to where the current file is
        # located.
        if text[0] == "/":
            head = "."
        else:
            # Text will be pointing at a directory or file, relative to
            # where the parent file is living.
            # head gets us the directory where the parent file lives.
            head, tail = os.path.split(filename)
        if head[-1] != '/' and text[0] != '/':
            combined_path = "%s/%s" % (head, text)
        else:
            combined_path = "%s%s" % (head, text)
        # If the path contains a double-slash, that works on the OS but not in the
        # browser so we need to explicitly check for it.
        if "//" in combined_path:
            return combined_path
        # If we're looking at a directory, make sure there is an index file in it.
        if combined_path[-1] == '/':
            combined_path += "index.html"
        if self.verbose >= 2:
            print(("Validating file: constituent parts are '%s' and '%s',"
                   " combined path is '%s'") % (head, text, combined_path))
        # needs to be a file or directory ...
        result = os.path.exists(combined_path)
        if result:
            return None
        else:
            return combined_path

    def matched_skip(self, text, skip_list):
        if skip_list is not None:
            for s in skip_list:
                if text.startswith(s):
                    return True
        return False

    def validate_link(self, filename, text):
        # Clean up the text first ...
        if text is not None:
            text = text.strip()
        if text is None or text == "" or text[0] == "#":
            # or matched_redirect(text):
            return None
        else:
            # Some links don't have the transport on them to ensure that they work
            # whether the user is coming via http or https, so add it if it is
            # missing.
            if len(text) > 2 and text[:2] == "//":
                text = "https:" + text
            # Check the URL to see if it is a web link - that is all we check.
            o = urlparse(text)
            if not self.args.noexternal and (o.scheme == "http" or o.scheme == "https"):
                # We use "self.file_link_pairs" to track which files reference which
                # URLs - we only check URLs *once* but then flag up all
                # refernces to the link.
                if [filename, text] not in self.file_link_pairs:
                    self.file_link_pairs.append([filename, text])
                # ... only check the links once!
                if text not in self.unique_links:
                    self.unique_links.append(text)
                return None  # Postpone the decision for now ...
            elif not self.args.nointernal and o.scheme == "":
                return self.validate_file_link(filename, text)
            # If skipping stuff, return the answer of no problems ...
            return None

    def output_status(self, code, value):

        if self.status_count % 100 == 0:
            end = "\n"
        else:
            end = ""
        print(code, end=end, flush=True)
        self.status_count += 1
        return value

    async def async_check_link(self, session, url):
        # Check that the host resolves, but only if it isn't in the DNS skip list
        parts = urlparse(url)
        if parts.netloc not in self.dns_skip:
            try:
                socket.gethostbyname(parts.netloc)  # noqa
            except socket.gaierror as err:
                return self.output_status('D', 1)
        # Now try to validate the URL
        try:
            async with session.head(
                    url,
                    allow_redirects=True,
                    headers=self.CHROME) as response:
                if response.status == 404 or response.status == 405:
                    # Some sites return 404/405 for HEAD requests, so we need to
                    # double-check with a full request.
                    async with session.get(
                            url,
                            allow_redirects=True,
                            headers=self.CHROME) as response:
                        if response.status != 404 and response.status != 405:
                            return self.output_status('.', 0)
                        return self.output_status('X', response.status)
                else:
                    if (response.status < 400 or
                            response.status > 499):
                        return self.output_status('.', 0)
                    else:
                        if self.verbose >= 3:
                            print(response.status, response.url)
                        # We only really care about full-on failures, i.e. 404.
                        # Other status codes can be returned just because we aren't
                        # using a browser, even if we do provide the agent string
                        # for Chrome.
                        return self.output_status('_', 0)
        # (Non-)Fatal errors
        except socket.gaierror as err:
            print("Error while checking %s: %s" % (url, err))
            return self.output_status('a', -2)
        # Non-fatal errors, but indicate which error we are getting
        except aiohttp.client_exceptions.ClientConnectorError:
            return self.output_status('b', -3)
        except aiohttp.client_exceptions.ServerTimeoutError:
            return self.output_status('c', -4)
        except concurrent.futures._base.CancelledError:
            return self.output_status('d', -5)
        except concurrent.futures._base.TimeoutError:
            return self.output_status('e', -6)
        except aiohttp.client_exceptions.ClientOSError:
            return self.output_status('f', -7)
        except aiohttp.client_exceptions.ServerDisconnectedError:
            return self.output_status('g', -8)
        except aiohttp.client_exceptions.ClientResponseError:
            return self.output_status('h', -9)

    async def async_check_web(self, session, links):
        results = await asyncio.gather(
            *[self.async_check_link(session, url) for url in links]
        )
        # That gets us a collection of the responses, matching up to each of
        # the tasks, so loop through the links again and the index counter
        # will point to the corresponding result.
        i = 0
        for l in links:
            if l not in self.html_cache_results:
                if results[i] == 0:
                    self.html_cache_results[l] = None
                elif results[i] > 0:
                    self.html_cache_results[l] = "%s [%d]" % (l, results[i])
            i += 1

    # Perform an async check of all of the web links we've collected then
    # build up a list of the affected files for the faulty links.

    async def check_unique_links(self):
        self.status_count = 1

        web_failed_links = []
        print("Checking %s web links ..." % len(self.unique_links))
        # Force IPv4 only to avoid
        # https://stackoverflow.com/questions/40347726/python-3-5-asyincio-and-aiohttp-errno-101-network-is-unreachable
        conn = aiohttp.TCPConnector(
            family=socket.AF_INET,
            verify_ssl=False,
            limit=500
        )
        async with aiohttp.ClientSession(connector=conn,
                                         conn_timeout=60) as session:
            await self.async_check_web(session, self.unique_links)
        for p in self.file_link_pairs:
            # p[0] is the file path and p[1] is the URL.
            if (p[1] in self.html_cache_results and
                    self.html_cache_results[p[1]] is not None):
                error = [p[0], self.html_cache_results[p[1]]]
                if error not in web_failed_links:
                    web_failed_links.append(error)
        return web_failed_links

    def remove_skip_elements(self, soup, a_links):
        """
        Removes any elements that have explicitly been set to skip
        """
        # Linaro specific ... find any "edit on GitHub" links so that
        # they can be EXCLUDED from the list of links to check. The reason
        # why is because if this is a new page (i.e. in a Pull Request),
        # the file won't exist in the repository yet and so the link to
        # the page would fail.
        for skip_element_tag, skip_element_id in self.skip_elements.items():
            gh_links = soup.find_all(skip_element_tag, id=skip_element_id)
            for g in gh_links:
                a_links.remove(g)
        return a_links

    def check_file(self, filename, skip_list):
        """
        For the specified file, read it in and then check all of the links in it.
        """
        file_failed_links = []
        # Check file is not in skip list
        if not self.matched_skip(filename, skip_list):
            try:
                # Retreive contents of file
                with open(filename, "r") as my_file:
                    data = my_file.read()
                # Setup new BeautifulSoup parser
                soup = BeautifulSoup(data, 'html.parser')
                # Find all Anchor tags (<a></a>)
                a_links = soup.find_all('a')
                # Remove any elements that have been set to be skipped.
                a_links = self.remove_skip_elements(soup, a_links)
                # Loop over all <a> links and check if links are valid
                for link in a_links:
                    # Validate link
                    result = self.validate_link(filename, link.get('href'))
                    # Check to see if an error was found
                    if result is not None:
                        # Create new list
                        error = [filename, result]
                        # Check the error hasn't already been found for this file
                        if error not in file_failed_links:
                            # Append error THIS file's broken links.
                            file_failed_links.append(error)
                # Check images that have a src="" attribute
                # Lazy loaded images should also be checked
                # TODD add data-src support.
                images_list = soup.find_all('img')
                for image in images_list:
                    # Validate link
                    result = self.validate_link(filename, image.get('src'))
                    # Check to see if result contains errors
                    if result is not None:
                        # Create new list
                        error = [filename, result]
                        if error not in file_failed_links:
                            file_failed_links.append(error)
            except Exception as exception:
                print("FAILED TO READ '%s' - %s" % (filename, str(exception)))
        return file_failed_links

    def failures_to_dict(self, list_of_failures):
        failure_dict = {}
        for failure in list_of_failures:
            failed_file = self.drop_dot(failure[0])
            url = self.drop_dot(failure[1])
            if failed_file in failure_dict:
                failure_dict[failed_file].append(url)
            else:
                failure_dict[failed_file] = [url]
        return failure_dict

    # Scan the specified directory, ignoring anything that matches skip_list.

    def scan_directory(self, path, skip_list):
        """
        Scans a directory for html files to check for broken links
        """
        soft_failure = False
        # Get the all the HTML files in <path>
        html_files = self.get_all_html_files(path)
        # Get the total files we're checking
        if self.args.file is not None:
            total = len(self.args.file)
        else:
            total = len(html_files)
        # Loop over all HTML files found
        count = 1
        for html_file in html_files:
            # Check to see if a file check list is set
            # and if the file is in the check list.
            if self.args.file is None or html_file in self.args.file:
                print("(%s/%s) Checking '%s'" % (count, total, html_file))
                count += 1
                # Check the file for broken links
                results = self.check_file(html_file, skip_list)
                for broken_link in results:
                    if broken_link not in self.failed_links:
                        self.failed_links.append(broken_link)

        if len(self.unique_links) == 0:
            print("No web links to check.")
        else:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            cul_result = loop.run_until_complete(self.check_unique_links())
            loop.close()
            # If we are NOT reporting broken external links as an error,
            # report them as warnings if there are any.
            if self.args.no_external_errors:
                if cul_result != []:
                    print("\n\nWARNING! %s failed external links have been "
                          "found:\n" % len(cul_result))
                    self.report_failed_links(cul_result)
                    soft_failure = True
            else:
                # Can do a simple append here because these are all web failures
                # and so don't need to check if the failure already exists in the
                # list.
                self.failed_links += cul_result
        if self.failed_links != []:
            if self.output_file is not None:
                save_out = sys.stdout
                fsock = open(self.output_file, 'w')
                sys.stdout = fsock
            else:
                print("")
            print("%s failed links have been found:\n" %
                  len(self.failed_links))
            self.report_failed_links(self.failed_links)
            if self.output_file is not None:
                sys.stdout = save_out
                fsock.close()
            sys.exit(1)
        if soft_failure:
            print("\nLinks have been checked; warnings reported.")
        else:
            print("\nLinks have been successfully checked.")

    def report_failed_links(self, failed_links):
        failure_dict = self.failures_to_dict(failed_links)
        for file in sorted(failure_dict):
            print("%s:" % file)
            for ref in failure_dict[file]:
                print("   %s" % ref)


if __name__ == '__main__':

    link_checker = JekyllLinkChecker()
