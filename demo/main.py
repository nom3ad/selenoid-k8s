#!/bin/env python
import time

from selenium import webdriver
from selenium.webdriver.common.keys import Keys

driver = webdriver.Remote(
    command_executor="http://127.0.0.1:4444/wd/hub",
    # command_executor="http://10.96.156.23:4444/wd/hub", # selnoid
    # command_executor="http://10.96.147.40:8085",  # healenium
    # command_executor="http://168.138.103.201:8085",  # healenium
    desired_capabilities={
        "browserName": "chrome",
        # "browserName": "firefox",
        # "browserVersion": "latest",
        # "video": "True",
        # "platform": "WIN10",
        # "platformName": "linux",
    },
)
# driver = webdriver.Firefox()
# driver = webdriver.Chrome()

print(f"{driver.session_id=}")

with driver:
    driver.get("https://www.python.org")
    print(f"{driver.title=}")
    search_bar = driver.find_element(by="name", value="q")
    search_bar.clear()
    search_bar.send_keys("getting started with python")
    search_bar.send_keys(Keys.RETURN)
    time.sleep(3)
    print(f"{driver.current_url=}")
