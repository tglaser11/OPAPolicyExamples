# https://play.openpolicyagent.org/p/ZVbqSEmZwC

package advisor.pers.authz

import future.keywords.in

default can_trade = false
default margin_account = false
default pershing_role = "planner"

can_trade {
	user_is_admin
}

pershing_role = "planner" {
	user_is_CFA
    not user_has_series7
}

pershing_role = "trader" {
	user_has_series7
    not user_is_CFA
}

pershing_role = "supertrader" {
	user_has_series7
    user_is_CFA
}
    
user_is_admin {
	"admin" in data.user_roles[input.user]
}

user_has_series7 {
	"series7" in data.credentials[input.user]
}

user_is_CFA {
	"cfa" in data.credentials[input.user]
}

margin_account {
	data.tenure[input.user] > 20
}