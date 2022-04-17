package http.request.authz

import future.keywords.in

# deny allow by default
default allow = false

# Allow with valid JWT
# User is manager role
allow {
    valid_jwt
    user_is_manager
    advisor_connected_with_client
}

# Test to see if user is manager
user_is_manager {
	Roles[_] == "Manager"
}

# check external data
contracts := data.contracts


# identify client
clientId := parsed_path[count(parsed_path)-1]

#### check advisor has role on contract of owner
#### would be replaced by external service call
# find all indices i that have value of clientId
# TODO
advisor_connected_with_client {
    some i
    contracts[i].advisor_user == subject
}


# Rego fucntion to validate JWT
valid_jwt := io.jwt.verify_hs256(jwt, certificate)

# Decode JWT and extract claims
decoded_jwt := io.jwt.decode(jwt)
subject := decoded_jwt[1].sub
Roles := decoded_jwt[1].Role

# parse path
parsed_path := split(path, "/")

# passed in inputs from SpringOPA
jwt := input.encodedJwt
method := input.method      # GET, POST, etc.
path := input.path          # ex. /item/1234

# Todo:  Find a way to pull in IdP cert dynamically
certificate := "qwertyuiopasdfghjklzxcvbnm123456"