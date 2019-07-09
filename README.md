# jekyll-link-checker
A Docker container used by Linaro's web site build process.

The container provides a self-contained link checking tool. This avoids needing to install directly on the host the packages required to run the tool.

This link checking tool has been written to check a local copy of a web site, e.g. a static web site built by Jekyll. That allows it to very quickly validate internal web links as they should be referencing files within the directory being scanned. The tool will also scan external links and report on any that don't work.

There are a lot of command line options to control the behaviour of the tool and these are explained in the [wiki](https://github.com/linaro-its/jekyll-link-checker/wiki/Using-the-link-checker).


# Building
## Prerequisites
* An operating system capable of running [Docker](https://www.docker.com/)
* Enough free RAM and disc space

Building has been tested with [Docker Community Edition](https://www.docker.com/community-edition#/download) under [Ubuntu](https://www.ubuntu.com/) and [Windows 10](https://www.microsoft.com/en-us/windows).

## Building
Build the container in the usual way, e.g.

`docker build --rm -t "linaroits/linkcheck:<tag>" .`

**Important:** If developing a variant of this container, e.g. to try out new facilities in the link checking code, use a personal tag reference and then specify that tag when running the link checking script included in each website repository, e.g.:

`LINKCHECK="personaltag" ../check-links.sh`

If you omit `<tag>`, Docker will default to tagging the container as `latest` which could cause confusion if testing local changes. For that reason, Linaro-provided versions of the linkcheck container will display the Bamboo build reference at the start of the process, e.g.:

```
Linaro Link Checker (build by bamboo.linaro.org: ABC-DEF)
...
```

The tool will, if it has access to the Internet, check Docker Hub to see if the latest image is being used and warn if it isn't.

Built containers can also be found on Docker Hub for your convenience.
