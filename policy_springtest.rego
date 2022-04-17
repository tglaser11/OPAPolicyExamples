package http.request.authz

# deny allow by default
default allow = false

# Allow with valid JWT
allow {
    valid_jwt
}

# Rego fucntion to validate JWT
valid_jwt := io.jwt.verify_hs256(jwt, certificate)

# Decode JWT and extract claims
decoded_jwt := io.jwt.decode(jwt)
subject := decoded_jwt[1].sub

# passed in inputs from SpringOPA
jwt := input.encodedJwt
method := input.method      # GET, POST, etc.
path := input.path          # ex. /item/1234

# Todo:  Find a way to pull in IdP cert dynamically
certificate := "qwertyuiopasdfghjklzxcvbnm123456"