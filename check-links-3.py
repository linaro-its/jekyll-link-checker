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

# The link checking process depends on whether it is a relative
# or absolute link. If it is a relative link, a file is looked for
# that matches the relative path.
#
# If it is an absolute link, the pair of filename and link are stored,
# along with a list of unique links to be checked. At the end of the
# scan, all of the unique links are checked in an async process and
# the results stored. Those results are then used to update the list
# of filename/link pairs.


CHROME = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 6.1) '
                  'AppleWebKit/537.36 (KHTML, like Gecko) '
                  'Chrome/41.0.2228.0 Safari/537.36'
}


def drop_dot(foo):
    if foo != "" and foo[0] == '.':
        return foo[1:]
    return foo


def get_all_html_files(path):
    result = []
    for root, dirs, files in os.walk(path):
        for name in files:
            if name.endswith((".html", ".htm")):
                f = os.path.join(root, name)
                if f not in result:
                    if verbose >= 3:
                        print("File scan: adding '%s'" % f)
                    result.append(f)
        for d in dirs:
            files_in_d = get_all_html_files(join(root, d))
            if files_in_d:
                for f in files_in_d:
                    if f not in result:
                        if verbose >= 3:
                            print("File scan: adding '%s'" % f)
                        result.append(f)
    return result


def validate_file_link(filename, text):
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
    if verbose >= 2:
        print(("Validating file: constituent parts are '%s' and '%s',"
               " combined path is '%s'") % (head, text, combined_path))
    # needs to be a file or directory ...
    result = os.path.exists(combined_path)
    if result:
        return None
    else:
        return combined_path


def matched_skip(text, skip_list):
    if skip_list is not None:
        for s in skip_list:
            if text.startswith(s):
                return True
    return False


def validate_link(filename, text):
    global file_link_pairs
    global unique_links
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
        if not args.noexternal and (o.scheme == "http" or o.scheme == "https"):
            # We use "file_link_pairs" to track which files reference which
            # URLs - we only check URLs *once* but then flag up all
            # refernces to the link.
            if [filename, text] not in file_link_pairs:
                file_link_pairs.append([filename, text])
            # ... only check the links once!
            if text not in unique_links:
                unique_links.append(text)
            return None  # Postpone the decision for now ...
        elif not args.nointernal and o.scheme == "":
            return validate_file_link(filename, text)
        # If skipping stuff, return the answer of no problems ...
        return None


def output_status(code, value):
    global status_count

    if status_count % 100 == 0:
        end = "\n"
    else:
        end = ""
    print(code, end=end, flush=True)
    status_count += 1
    return value


async def async_check_link(session, url):
    # Check that the host resolves, but only if it isn't in the DNS skip list
    parts = urlparse(url)
    if parts.netloc not in dns_skip:
        try:
            foo = socket.gethostbyname(parts.netloc)  # noqa
        except socket.gaierror as err:
            return output_status('D', 1)
    # Now try to validate the URL
    try:
        async with session.head(
                url,
                allow_redirects=True,
                headers=CHROME) as response:
            if response.status == 404 or response.status == 405:
                # Some sites return 404/405 for HEAD requests, so we need to
                # double-check with a full request.
                async with session.get(
                        url,
                        allow_redirects=True,
                        headers=CHROME) as response:
                    if response.status != 404 and response.status != 405:
                        return output_status('.', 0)
                    return output_status('X', response.status)
            else:
                if (response.status < 400 or
                        response.status > 499):
                    return output_status('.', 0)
                else:
                    if verbose >= 3:
                        print(response.status, response.url)
                    # We only really care about full-on failures, i.e. 404.
                    # Other status codes can be returned just because we aren't
                    # using a browser, even if we do provide the agent string
                    # for Chrome.
                    return output_status('_', 0)
    # (Non-)Fatal errors
    except socket.gaierror as err:
        print("Error while checking %s: %s" % (url, err))
        return output_status('a', -2)
    # Non-fatal errors, but indicate which error we are getting
    except aiohttp.client_exceptions.ClientConnectorError:
        return output_status('b', -3)
    except aiohttp.client_exceptions.ServerTimeoutError:
        return output_status('c', -4)
    except concurrent.futures._base.CancelledError:
        return output_status('d', -5)
    except concurrent.futures._base.TimeoutError:
        return output_status('e', -6)
    except aiohttp.client_exceptions.ClientOSError:
        return output_status('f', -7)
    except aiohttp.client_exceptions.ServerDisconnectedError:
        return output_status('g', -8)
    except aiohttp.client_exceptions.ClientResponseError:
        return output_status('h', -9)


async def async_check_web(session, links):
    results = await asyncio.gather(
        *[async_check_link(session, url) for url in links]
    )
    # That gets us a collection of the responses, matching up to each of
    # the tasks, so loop through the links again and the index counter
    # will point to the corresponding result.
    i = 0
    for l in links:
        if l not in html_cache_results:
            if results[i] == 0:
                html_cache_results[l] = None
            elif results[i] > 0:
                html_cache_results[l] = "%s [%d]" % (l, results[i])
        i += 1


# Perform an async check of all of the web links we've collected then
# build up a list of the affected files for the faulty links.
async def check_unique_links():
    global status_count
    status_count = 1

    web_failed_links = []
    print("Checking %s web links ..." % len(unique_links))
    # Force IPv4 only to avoid
    # https://stackoverflow.com/questions/40347726/python-3-5-asyincio-and-aiohttp-errno-101-network-is-unreachable
    conn = aiohttp.TCPConnector(
        family=socket.AF_INET,
        verify_ssl=False,
        limit=500
    )
    async with aiohttp.ClientSession(connector=conn,
                                     conn_timeout=60) as session:
        await async_check_web(session, unique_links)
    for p in file_link_pairs:
        # p[0] is the file path and p[1] is the URL.
        if (p[1] in html_cache_results and
                html_cache_results[p[1]] is not None):
            error = [p[0], html_cache_results[p[1]]]
            if error not in web_failed_links:
                web_failed_links.append(error)
    return web_failed_links


# For the specified file, read it in and then check all of the links in it.
def check_file(filename, skip_list):
    file_failed_links = []
    if not matched_skip(filename, skip_list):
        try:
            with open(filename, "r") as myfile:
                data = myfile.read()
            soup = BeautifulSoup(data, 'html.parser')
            a_links = soup.find_all('a')
            # Linaro specific ... find any "edit on GitHub" links so that
            # they can be EXCLUDED from the list of links to check. The reason
            # why is because if this is a new page (i.e. in a Pull Request),
            # the file won't exist in the repository yet and so the link to
            # the page would fail.
            gh_links = soup.find_all('a', id="edit_on_github")
            for g in gh_links:
                a_links.remove(g)
            for link in a_links:
                result = validate_link(filename, link.get('href'))
                if result is not None:
                    error = [filename, result]
                    if error not in file_failed_links:
                        file_failed_links.append(error)
            # Check linked images
            img_links = soup.find_all('img')
            for link in img_links:
                result = validate_link(filename, link.get('src'))
                if result is not None:
                    error = [filename, result]
                    if error not in file_failed_links:
                        file_failed_links.append(error)
        except Exception as exception:
            print("FAILED TO READ '%s' - %s" % (filename, str(exception)))
    return file_failed_links


def failures_to_dict(list_of_failures):
    failure_dict = {}
    for f in list_of_failures:
        file = drop_dot(f[0])
        url = drop_dot(f[1])
        if file in failure_dict:
            failure_dict[file].append(url)
        else:
            failure_dict[file] = [url]
    return failure_dict


# Scan the specified directory, ignoring anything that matches skip_list.
def scan_directory(path, skip_list):
    global failed_links
    global file_link_pairs
    global unique_links
    failed_links = []
    file_link_pairs = []
    unique_links = []

    soft_failure = False

    count = 1
    html_files = get_all_html_files(path)
    total = len(html_files)
    if args.file is not None:
        total = len(args.file)
    for hf in html_files:
        if args.file is None or hf in args.file:
            print("(%s/%s) Checking '%s'" % (count, total, hf))
            count += 1
            results = check_file(hf, skip_list)
            for r in results:
                if r not in failed_links:
                    failed_links.append(r)
    if len(unique_links) == 0:
        print("No web links to check.")
    else:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        cul_result = loop.run_until_complete(check_unique_links())
        loop.close()
        # If we are NOT reporting broken external links as an error,
        # report them as warnings if there are any.
        if args.no_external_errors:
            if cul_result != []:
                print("\n\nWARNING! %s failed external links have been "
                      "found:\n" % len(cul_result))
                report_failed_links(cul_result)
                soft_failure = True
        else:
            # Can do a simple append here because these are all web failures
            # and so don't need to check if the failure already exists in the
            # list.
            failed_links += cul_result
    if failed_links != []:
        if output_file is not None:
            save_out = sys.stdout
            fsock = open(output_file, 'w')
            sys.stdout = fsock
        else:
            print("")
        print("%s failed links have been found:\n" % len(failed_links))
        report_failed_links(failed_links)
        if output_file is not None:
            sys.stdout = save_out
            fsock.close()
        sys.exit(1)
    if soft_failure:
        print("\nLinks have been checked; warnings reported.")
    else:
        print("\nLinks have been successfully checked.")


def report_failed_links(failed_links):
    failure_dict = failures_to_dict(failed_links)
    for file in sorted(failure_dict):
        print("%s:" % file)
        for ref in failure_dict[file]:
            print("   %s" % ref)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Scan for broken links")
    parser.add_argument('-d', '--directory', nargs='?', default=None,
                        help='specifies the directory to scan')
    parser.add_argument('--skip-dns-check', nargs='?', default=None,
                        help='specifies text file of FQDNs to skip the DNS '
                        'check on')
    parser.add_argument('-s', '--skip-path', action='append',
                        help='specifies a path to skip when checking URLs')
    parser.add_argument('-v', '--verbose', action='count')
    parser.add_argument('-f', '--file', action='append',
                        help=('specifies a file to check;'
                              ' all non-specified files are ignored'))
    parser.add_argument('--nointernal', action='store_true',
                        help='skips checking of internal references')
    parser.add_argument('--noexternal', action='store_true',
                        help='skips checking of external references')
    parser.add_argument('-o', '--output', nargs='?', default=None,
                        help='specifies output file for error results')
    parser.add_argument('--no-external-errors', action='store_true',
                        help='ignores errors caused by external broken links')
    args = parser.parse_args()
    html_cache_results = {}
    dns_skip = []
    verbose = 0
    output_file = None

    print("Linaro Link Checker")

    if args.verbose is not None:
        verbose = args.verbose
        print("Verbosity is at level %s" % verbose)
    if args.skip_dns_check is not None:
        print("Loading FQDN skip list from %s" % args.skip_dns_check)
        try:
            dns_skip = list(open(args.skip_dns_check))
        except Exception as exception:
            print("Couldn't load FQDN skip list")
    if args.output is not None:
        output_file = args.output
    if args.directory is not None:
        print("Scanning '%s'" % args.directory)
        os.chdir(args.directory)
    if args.nointernal:
        print("Skipping internal link checking")
    if args.noexternal:
        print("Skipping external link checking")
    # For now, assume that we're just scanning the current directory. Add code
    # for file paths and possibly URLs at a future date ...
    scan_directory("./", args.skip_path)
