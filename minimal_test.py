import asyncio
import aiohttp

async def async_url_validation(session, url):
    """ Validate the URL. """
    async with session.get(
            url) as response:
        print(response)
        return response.status

async def async_check_web(session, links):
    """ Check all external links. """
    results = await asyncio.gather(
        *[async_url_validation(session, url) for url in links]
    )
    # That gets us a collection of the responses, matching up to each of
    # the tasks, so loop through the links again and the index counter
    # will point to the corresponding result.
    i = 0
    for link in links:
        print(link, results[i])
        i += 1

async def check_unique_links():
    UNIQUE_LINKS = [
        "https://twitter.com/linaroorg",
        "https://www.linaro.org"
    ]

    async with aiohttp.ClientSession() as session:
        await async_check_web(session, UNIQUE_LINKS)

loop = asyncio.get_event_loop()
cul_result = loop.run_until_complete(check_unique_links())
loop.close()
