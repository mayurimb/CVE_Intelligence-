# CVE_Intelligence/utils.py
from dotenv import load_dotenv
import os

load_dotenv()

def get_env_variable(name):
    value = os.getenv(name)
    if value is None:
        raise EnvironmentError(f"{name} is not set in environment.")
    return value
