# jekyll-link-checker

This tool has been written to check the HTML files in a locally-stored directory for internal and external links, making sure that internal links reference a valid file or directory within the directory being scanned and that external links give a valid response.

The script was primarily written as a check step for Linaro when one of the Jekyll-based websites is rebuilt. The script has been bundled into a Docker container to make everything self-container - it avoids the need to install any required packages directly on the host.

There are a lot of command line options to control the behaviour of the tool and these are explained in the [wiki](https://github.com/linaro-its/jekyll-link-checker/wiki/Using-the-link-checker).

## Development

### Prerequisites

* An operating system capable of running [Docker](https://www.docker.com/)
* Enough free RAM and disc space

Building has been tested with [Docker Community Edition](https://www.docker.com/community-edition#/download) under [Ubuntu](https://www.ubuntu.com/) and [Windows 10](https://www.microsoft.com/en-us/windows).

### Building

Build the container in the usual way, e.g.

`docker build --rm -t "linaroits/linkcheck:<tag>" .`

**Important:** If developing a variant of this container, e.g. to try out new facilities in the link checking code, use a personal tag reference and then specify that tag when running the link checking script included in each website repository, e.g.:

`LINKCHECK="personaltag" ../check-links.sh`

If you omit `<tag>`, Docker will default to tagging the container as `latest` which could cause confusion if testing local changes. For that reason, Linaro-provided versions of the linkcheck container will display a build reference at the start of the process, e.g.:

``` text
Contained built by GitHub. Build reference: ABC-DEF
...
```

The tool will, if it has access to the Internet, check Docker Hub to see if the latest image is being used and warn if it isn't.

Built containers can also be found on Docker Hub for your convenience.

## Using the tool

The git repositories for Linaro websites include a shell script that can be used to simplify the process of using the tool. For example, <https://github.com/Linaro/website/blob/master/check-links.sh>. This script is used by going into the directory to be scanned and then going `../check-links.sh`, assuming that the `check-links.sh` script is located in the directory *above* the directory to be scanned.

If you want to run the Docker container directly, the following should be useful as a starting point:

``` bash
docker run --rm -it -v /etc/passwd:/etc/passwd:ro -v /etc/group:/etc/group:ro -u "$(id -u)":"$(id -g)" -v `pwd`:/srv linaroits/linkcheck
```

Additional script parameters can be provided at the end of the `docker run` command and they will be passed to the link checker script.

The use of `/etc/passwd`, `/etc/group` and `id` ensures that the script running in the container can successfully access the website files in the mounted directory.
