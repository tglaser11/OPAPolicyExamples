package policy_test

import data.policy.allow

test_allow_is_false_by_default {
    not allow
}

test_allow_if_admin {
    allow with input as {
        "user": {
            "roles": ["admin"]
        }
    }
}

test_deny_if_not_admin {
    not allow with input as {
        "user" : {
            "roles": ["architect"]
        }
    }
}

test_allow_if_get_on_public {
    allow with input as {
        "request": {
            "method": "GET",
            "path": "/public"
        }
    }
    allow with input as {
        "request": {
            "method": "GET",
            "path": "/public/pictures"
        }
    }
}