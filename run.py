import logging

logging.basicConfig(level=logging.INFO)
from lynk.core import Lynk

Lynk.from_usernames("tpad", "phone")
