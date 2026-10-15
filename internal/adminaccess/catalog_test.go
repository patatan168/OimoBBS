package adminaccess

import "testing"

func TestPermissionCombinations(t *testing.T) {
	for _, role := range []string{"moderator", "board_admin", "site_admin"} {
		for _, p := range Permissions() {
			if err := Validate(role, []string{p.Value}); err != nil {
				t.Fatal(err)
			}
			if Granted(role, nil, p.Value) != IncludesExtras(role) {
				t.Fatal("implicit grant", role, p.Value)
			}
			if !Granted(role, []string{p.Value}, p.Value) {
				t.Fatal("explicit grant")
			}
		}
	}
	for _, role := range []string{"viewer", "reporter", "unknown", ""} {
		if Validate(role, nil) == nil {
			t.Fatal("removed role", role)
		}
	}
	for _, value := range []string{"private_posts.read", "evidence.read", "evidence.hold", "evidence.export", "evidence.transfer", "unknown"} {
		if Validate("site_admin", []string{value}) == nil || Granted("site_admin", nil, value) {
			t.Fatal("removed permission", value)
		}
	}
}
