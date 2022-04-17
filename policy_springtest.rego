package http.request.authz

import future.keywords.in

### POLICY ###
# Deny all access to a client record unless all conditions are met:
# --user has valid JWT
# --user role is manager
# --user has servicing role (advisor_user) on a contract with that 
#   has client listed
###############
### TODO ###
# --Illustrate Unit Tests
# --Illustrate use of remote API PIP call using http.send
# --Illustrate how to filter multiple clients using /client route
##############

# deny allow by default
default allow = false

#### All need to be TRUE for allow = TRUE
# Allow with valid JWT
# User is manager role
# Advisor has servicing relationshiop with client
allow {
    valid_jwt
    user_is_manager
    advisor_connected_with_client
}

# Test to see if user is manager
user_is_manager {
	Roles[_] == "Manager"
}

# check external data from mock datastore
contracts := data.contracts

#### check advisor has role on contract of owner
#### would be replaced by external service call
# TODO -- illustrate this with http.send remote API call (more efficient)
# TODO -- find a more efficient way to search through passed in data?
advisor_connected_with_client {
    # Iterate through contracts
    some i
    # Conditions are automatically evaluated as AND
    contracts[i].advisor_user == subject
    contracts[i].owner_leid == clientId
}

# identify requested client leid
clientId := parsed_path[count(parsed_path)-1]

# Rego fucntion to validate JWT
valid_jwt := io.jwt.verify_hs256(jwt, certificate)

# Decode JWT and extract any relevant claims
decoded_jwt := io.jwt.decode(jwt)
subject := decoded_jwt[1].sub
Roles := decoded_jwt[1].Role

# parse path
parsed_path := split(path, "/")

# passed in inputs from SpringOPA
jwt := input.encodedJwt
method := input.method      # GET, POST, etc.
path := input.path          # ex. /item/1234

# Todo:  Find a way to pull in IdP cert dynamically for validation
certificate := "qwertyuiopasdfghjklzxcvbnm123456"