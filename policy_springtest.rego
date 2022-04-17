package http.request.authz

default allow = false

allow {
    valid_jwt
}

valid_jwt := io.jwt.verify_hs256(jwt, certificate)

decoded_jwt := io.jwt.decode(jwt)
subject := decoded_jwt[1].sub

jwt := input.encodedJwt
certificate := "qwertyuiopasdfghjklzxcvbnm123456"