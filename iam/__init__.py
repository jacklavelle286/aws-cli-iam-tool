import boto3
import json
import os
import subprocess
import getpass
from simple_term_menu import TerminalMenu
iam_client = boto3.client("iam")

