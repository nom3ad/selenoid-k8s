#!/bin/env python
import time

from selenium import webdriver
from selenium.webdriver.common.keys import Keys

chromeServerlessArgs = [
    # https://github.com/alixaxel/chrome-aws-lambda/blob/master/source/index.ts
    "headless",
    "single-process",
    # "start-maximized",
    "allow-running-insecure-content",
    "autoplay-policy=user-gesture-required",
    "disable-component-update",
    "disable-domain-reliability",
    "disable-features=AudioServiceOutOfProcess,IsolateOrigins,site-per-process",
    "disable-print-preview",
    "disable-setuid-sandbox",
    "disable-site-isolation-trials",
    "disable-speech-api",
    "disable-web-security",
    "disk-cache-size=33554432",
    "enable-features=SharedArrayBuffer",
    "hide-scrollbars",
    "ignore-gpu-blocklist",
    "in-process-gpu",
    "mute-audio",
    "no-default-browser-check",
    "no-pings",
    "no-sandbox",
    "no-zygote",
    "use-gl=swiftshader",
    "window-size=1920,1080",
    # "disable-gpu",
    "disable-dev-shm-usage",
]
driver = webdriver.Remote(
    command_executor="http://127.0.0.1:4444/wd/hub",
    # command_executor="http://10.96.156.23:4444/wd/hub", # selnoid
    # command_executor="http://10.96.147.40:8085",  # healenium
    # command_executor="http://168.138.103.201:8085",  # healenium
    desired_capabilities={
        # "browserName": "chrome",
        # "goog:chromeOptions": {"args": chromeServerlessArgs},
        "browserName": "firefox",
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
