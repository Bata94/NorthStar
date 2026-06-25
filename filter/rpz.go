package filter

type RPZEntry struct {
	List   *List
	Action string
}

type RPZSet struct {
	entries []RPZEntry
}

func NewRPZSet(rpzConfigs []struct{ Path, Action string }) (*RPZSet, error) {
	rs := &RPZSet{}
	for _, rc := range rpzConfigs {
		if rc.Path == "" {
			continue
		}
		l, err := New([]string{rc.Path})
		if err != nil {
			return nil, err
		}
		action := rc.Action
		if action == "" {
			action = "nxdomain"
		}
		rs.entries = append(rs.entries, RPZEntry{List: l, Action: action})
	}
	return rs, nil
}

func (rs *RPZSet) Match(domain string) (string, bool) {
	if rs == nil {
		return "", false
	}
	for _, e := range rs.entries {
		if e.List.Match(domain) {
			return e.Action, true
		}
	}
	return "", false
}

func (rs *RPZSet) Reload(rpzConfigs []struct{ Path, Action string }) error {
	var entries []RPZEntry
	for _, rc := range rpzConfigs {
		if rc.Path == "" {
			continue
		}
		l, err := New([]string{rc.Path})
		if err != nil {
			return err
		}
		action := rc.Action
		if action == "" {
			action = "nxdomain"
		}
		entries = append(entries, RPZEntry{List: l, Action: action})
	}
	rs.entries = entries
	return nil
}

func (rs *RPZSet) Len() int {
	if rs == nil {
		return 0
	}
	return len(rs.entries)
}
