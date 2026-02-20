# URL-shortening web service with an Authentication service

This is the implementation of URL shortener service implemented with Flask and the Authentication with JSON web tokens.

## Installation

```bash
pip3 install flask
```

```bash
pip install PyJWT
```

You can now run the service

## Usage

### Running the service

First, run the Authentication service:

```bash
flask --app auth-service run
```

Then run url-shortnering service in a seperate terminal:

```bash
flask --app url-shortener run
```

### Usage of the service

Methods implemneted for the authentication services are given below:

- POST /users
  - Creates a new user with the provided username and password.
  - Returns 201 Created - when user is created sucessfully
  - Returns 409 Conflict - the user already exists.

- PUT /users
  - Updates the user's password when the correct old password is given.
  - Returns 200 OK - Sucessfully updated password.
  - Returns 403 Forbidden – incorrect old password given.
  - Returns 404 Not Found – the user does not exist.

- Patch /users
  - Updates the username if the correct password for that username is provided and the new username is not taken already.
  - Returns 200 OK - Sucessfully updated user details.
  - Returns 403 Forbidden - failed authentication.

- POST /users/login
  - Authenticates the user and generates a JWT if the given credentials are valid.
  - Returns 200 OK – JWT returned
  - Returns 403 Forbidden – invalid credentials

In the URL-shortening service we have added require jwt decorator to ensure all endpoints are accessible only to authenticated users.

- GET/
  - Returns the original URL associated with a given ID.
  - Returns 200 OK - all URL mappings for the authenticated user.
  - Returns 403 Fordidden - missing/invalid JWT

- POST/
  - Creates a new, shortened URL for a given URL.
  - Returns 201 Created - Returns created ID
  - Returns 400 Bad request URL value missing or invalid
  - Returns 403 Forbidden - missing/invalid JWT

- DELETE/
  - Deletes all shortened URLS for the authenticated user.
  - Returns 404 Not Found - nothing to delete
  - Returns 403 Forbidden - missing/invalid JWT

- GET/:id
  - Returns the full URL for a given ID
  - Returns 301 Redirects to the orginal URL
  - Returns 404 Not Found - given ID does not exist
- PUT/:id
  - Updates the URL associated with a given ID
  - Returns 200 OK – updated successfully
  - Returns 400 ERROR – URL not vald
  - Returns 404 Not Found – given ID does not exist
  - Returnd 403 Forbidden – missing/invalid JWT

- DELETE/:id
  - Deletes the shortener URL associated with a given ID
  - Returns 204 No Content – Deleted
  - Returns 404 Not Found – ID not found
  - Returns 403 Forbiddent - missing/invalid JWT

## Documentation

The entire service is implemented in ‘url-shortener.py’ and 'auth-service.py'
