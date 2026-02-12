# URL-shortening web service

This is the implementation of URL shortener service implemented with Flask.

## Installation

```bash
pip3 install flask
```

You can now run the service

## Usage

### Running the service

First, run the flask service:

```bash
flask --app url-shortener run
```

### Usage of the service

The service implements multiple methods which includes:

- GET/
  - Returns the shortened URLs
  - Returns 200 OK and a Json file.
  ```json
  {
    "ids:urls": {s1url, s2url ,... }
  }
  ```
- POST/
  - Creates a new, shortened URL for a given URL.
  - Request should contain a URL.
  - Returns 201 Created a new shortener URL created.
  - Returns 400 Bad request URL value missing or invalid

- DELETE/
  - Deletes all shortened URLS
  - Returns 404 at least one URL deleted
  - Returns 404 no URLs to delete

- GET/:id
  - Returns the full URL for a given ID
  - Returns 301 Get the Url of the given ID
  - Returns 404 Not Found
- PUT/:id
  - Updates the URL associated with an ID
  - Returns 200 OK – URL was updated
  - Returns 400 Bad request URL value missing or invalid

- DELETE/:id
  - Deletes the shortener URL associated with a ID
  - Returns 204 No Content – Deleted
  - Returns 404 Not Found – ID not found

## Documentation

The entire service is implemented in ‘url-shortener.py’’.
