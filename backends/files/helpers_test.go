package files

// Users returns a copy of the users of the current snapshot, for tests.
func (o *Checker) Users() map[string]*staticFileUser {
	users := o.snap.Load().users
	cp := make(map[string]*staticFileUser, len(users))
	for name, u := range users {
		cp[name] = &staticFileUser{password: u.password, aclRecords: append([]aclRecord(nil), u.aclRecords...)}
	}

	return cp
}
