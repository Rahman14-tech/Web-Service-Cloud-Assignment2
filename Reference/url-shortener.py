#!/bin/env python3

# URL SHORTENER.py
#   by Tim Müller
#
# Created:
#   03 Mar 2022, 14:25:23
# Last edited:
#   02 May 2023, 11:46:03
# Auto updated?
#   Yes
#
# Description:
#   Implements a simple URL-shortening RESTful service.
#   Build with the Flask (https://flask.palletsprojects.com/en/2.0.x/)
#   framework.
#
#   In this service, we try to assign a short identifier to each new URL. This
#   is implemented by choosing a number, and then 'decoding' that in much the
#   same way one would decode a number to a binary string, except with a
#   different base. See 'generate_id()' for this implementation.
#
#   The version in this repository has been extended to support JWTs to
#   identify a user. You can compare it to the reference implementation from
#   assignment 1 to see what has changed (most modern editors should allow you
#   to do this easily).
#

import base64
from http.client import responses
import os
import re
import requests
import sys
import typing

from flask import Flask, abort, redirect, request


### CONSTANTS ###
# Regular expressions that is used to check URLs for correctness.
# Taken from: https://stackoverflow.com/a/7995979
URL_CORRECTNESS_REGEX = (
    r"(?i)"                                                             # We activate the case-insensitivity extension for this regex. See the Python docs for more info: https://docs.python.org/3/library/re.html#regular-expression-syntax (see `(?...)`)
    r"^https?://"                                                       # Matches the start of the string (`^`) and then the `http://` or `https://` scheme
    r"(?:"                                                              # Matches either:
        r"(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?"         # A domain name, which consists of various subdomains separated by dots. Each of those matches an alphanumeric character, optionally followed by either 0-61 alphanumeric characters or dashes and another single alhpanumeric character. Finally, there is a letter-only toplevel domain name of 2-6 characters and an optional dot.
        r"|"                                                            # OR
        r"localhost"                                                        # We match 'localhost' literally
        r"|"                                                            # OR
        r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"                               # We match an IPv4 address, which are four sets of 1-3 digits.
    r")"
    r"(?::\d+)?"                                                        # Then we match an optional port, consisting of at least one digit. Note that the double colon is actually part of `(?:)`, which means a matched but not saved string.
    r"(?:/?|[/?]\S+)$"                                                  # Finally, we match an optional slash or a (slash or question mark) followed by at least one non-whitespace character. This effectively makes most of the paths wildcards, as they can be anything; but because paths can container arbitrary information, this is OK. At last we match the end-of-string boundary, `$`.
)





### GLOBAL VALUES ###
# Keeps track of the next numeric identifier
next_id = 0

# In-memory database of the URLs we have shortened
# Layout: contains ID/dictionary pairs, where each dictionary contains an url ("url") and a username ("name").
id_url_map = {}





### HELPER FUNCTIONS ###
def generate_id() -> str:
    """
        Generates a new identifier.

        Does so by serializing the global `next_id` to Base64 instead of ASCII
        for better compression.
    """

    # Don't forget to mark next_id as global, as otherwise updating it won't update the global variable
    global next_id

    # Get the ID and increment it
    identifier = next_id
    next_id += 1

    # We find the number of bytes we would need to represent the number.
    # We do this because Python's numbers are not really stored most efficiently per sé, so we take the minimum number of bytes
    n_bytes = 1 + identifier.bit_length() // 8

    # Serialize the number; we get it as an array of bytes (endianness does not matter, as long as
    # it's the same across all IDs, and then encode that byte string as Base64)
    sidentifier = base64.urlsafe_b64encode(identifier.to_bytes(n_bytes, sys.byteorder)).decode("utf-8")

    # We can strip the padding (`=`) from the identifier, since this is superfluous information (is purely reconstructable from the length of the string, if needed)
    while sidentifier[-1] == '=': sidentifier = sidentifier[:-1]

    # Done
    next_id += 1
    return sidentifier

def valid_url(url: str) -> bool:
    """
        Tries to match the given URL for correctness.

        Do so by simply matching it to a regular expression that performs this
        check (see the comment at URL_CORRECTNESS_REGEX).
    """

    # Match with a regex-expression
    return re.match(URL_CORRECTNESS_REGEX, url) is not None

def check_login(token: str) -> typing.Optional[str]:
    """
        Checks if the given token is a legal login token by verifying it with
        the authentication service.

        The location of the service is read from the AUTH_SVC environment variable.
    """

    # Get the auth service's location
    if "AUTH_SVC" in os.environ:
        auth_svc = os.environ["AUTH_SVC"]
    else:
        auth_svc = "http://localhost:5001"

    # Strip 'Bearer' from the token, if any
    if token[:7] == "Bearer ":
        token = token[7:]

    # Send a request to the authentication service
    try:
        r = requests.post(f"{auth_svc}/tokens", data={ "token": token })
    except requests.exceptions.RequestException as err:
        print(f"[ERROR] Token verification failed because we could not reach the authentication service ({auth_svc}/tokens): {err}", file=sys.stderr)
        return None

    # Check whether the request succeeded
    if r.status_code != 200:
        print(f"[ERROR] Token verification failed because authentication service ({auth_svc}/tokens) returned status code {r.status_code} ({responses[r.status_code] if r.status_code in responses else '???'})", file=sys.stderr)
        return None

    # Attempt to decode the response as JSON
    try:
        result = r.json()
    except requests.exceptions.JSONDecodeError as err:
        print(f"[ERROR] Token verification failed because authentication service ({auth_svc}/token) returned invalid JSON: {err}", file=sys.stderr)
        return None
    # Additionally assert it's only one of two types
    if result is not None and type(result) != str:
        print(f"[ERROR] Token verification failed because authentication service ({auth_svc}/token) returned non-string, non-null value '{result}'", file=sys.stderr)
        return None

    # We can directly return the value, since we now know it's either the username or None
    return result





### ENTRYPOINT ###
# Setup the application as a Flask app
app = Flask(__name__)





### API FUNCTIONS ###
# We use a flask macro to make let this function be called for the root URL ("/") and the specified HTTP methods.
@app.route("/", methods=['GET', 'POST', 'DELETE'])
def root():
    """
        Handles everything that falls under the API root (/).

        Supported methods:
         - GET: Returns a list of all the identifiers, as a JSON file.
         - POST: Asks to generate a new ID for the given URL (not in the URL itself, but as a form-parameter).
         - DELETE: Not supported for the general, so will return a 404 always.
        
        In all cases, if the user fails to authorize himself, a 403 is returned.
    """

    # Switch on the method used
    if request.method == "GET":
        # Get the authorization token
        if "Authorization" not in request.headers: abort(403)
        token = request.headers["Authorization"]

        # Check if the token is valid
        username = check_login(token)
        if username is None: abort(403)

        # Collect all the results for this user in a JSON map
        # We can simply return a dict, and flask will automatically serialize this to JSON for us
        return { "keys": [k for k, v in id_url_map.items() if v["name"] == username] }

    elif request.method == "POST":
        # Get the authorization token
        if "Authorization" not in request.headers: abort(403)
        token = request.headers["Authorization"]

        # Check if the token is valid
        username = check_login(token)
        if username is None: abort(403)

        # Try to get the URL
        if "url" not in request.form:
            return "URL not specified", 400
        url = request.form["url"]

        # Validate the URL
        if not valid_url(url):
            return "Invalid URL", 400

        # Generate a new identifier
        identifier = generate_id()

        # Insert it into the map for this user
        id_url_map[identifier] = { "url": url, "name": username }

        # Return it, with the 201 status code
        # When given a tuple, flask will automatically return it as text/status code
        return identifier, 201

    elif request.method == "DELETE":
        # Get the authorization token
        if "Authorization" not in request.headers: abort(403)
        token = request.headers["Authorization"]

        # Check if the token is valid
        username = check_login(token)
        if username is None: abort(403)

        # Get the list of stuff to delete for this user
        to_remove = [k for k, v in id_url_map.items() if v["name"] != username]
        if not to_remove: return "Nothing to delete", 404

        # Delete them otherwise
        for k in to_remove:
            del id_url_map[k]
        return "success", 204

# We use a flask macro to make let this function be called for any nested string under the root URL ("/:id") and the specified HTTP methods.
# The syntax of the identifier is '<string:id>', which tells flask it's a string (=any non-slash text) that is named 'id'
@app.route("/<string:id>", methods=['GET', 'PUT', 'DELETE'])
def url(id):
    """
        Handles everything that falls under a URL that is an identifier (/:id).

        Methods:
         - GET: Returns the URL behind the given identifier as a 301 result (moved permanently) so the browser automatically redirects.
         - PUT: Updates the given ID to point to the given URL (as a POST field). Returns a 200 on success, 400 on failure or 404 on not-existing ID.
         - DELETE: Deletes the ID/URL mapping based on the ID given, returning a 204 (no content).
    """

    # Switch on the method used
    if request.method == "GET":
        # No authentication needed, as this is public now

        # Check to see if we know this one
        if id in id_url_map:
            # We do! Redirect the user to it
            # The redirect() function will automatically set the correct headers and status code
            return redirect(id_url_map[id]["url"])
        else:
            # Resource not found
            abort(404)

    elif request.method == "PUT":
        # Get the authorization token
        if "Authorization" not in request.headers: abort(403)
        token = request.headers["Authorization"]

        # Check if the token is valid
        username = check_login(token)
        if username is None: abort(403)

        # Try to get the URL
        if "url" not in request.form:
            return "URL not specified", 400
        url = request.form["url"]

        # Validate the URL
        if not valid_url(url):
            return "Invalid URL", 400

        # Check if we know the ID
        if id not in id_url_map:
            abort(404)
        
        # Check if the user is allowed to change this value
        if id_url_map[id]["name"] != username: abort(403)

        # Update the ID
        id_url_map[id]["url"] = url

        # Done!
        return "success", 200

    elif request.method == "DELETE":
        # Get the authorization token
        if "Authorization" not in request.headers: abort(403)
        token = request.headers["Authorization"]

        # Check if the token is valid
        username = check_login(token)
        if username is None: abort(403)

        # Check if it exists
        if id in id_url_map:
            # Check if the user is allowed to delete it
            if id_url_map[id]["name"] != username: abort(403)

            # Remove it, then success
            del id_url_map[id]
            return "success", 204
        else:
            # Resource not found
            abort(404)
