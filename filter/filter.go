package filter

type Filter struct {
	blocklist *List
	allowlist *List
}

func NewFilter(blocklistPaths, allowlistPaths []string) (*Filter, error) {
	f := &Filter{}
	if len(blocklistPaths) > 0 {
		bl, err := New(blocklistPaths)
		if err != nil {
			return nil, err
		}
		f.blocklist = bl
	}
	if len(allowlistPaths) > 0 {
		al, err := New(allowlistPaths)
		if err != nil {
			return nil, err
		}
		f.allowlist = al
	}
	return f, nil
}

func (f *Filter) IsBlocked(domain string) bool {
	if f == nil {
		return false
	}
	if f.allowlist != nil && f.allowlist.Match(domain) {
		return false
	}
	if f.blocklist != nil && f.blocklist.Match(domain) {
		return true
	}
	return false
}

func (f *Filter) Reload(blocklistPaths, allowlistPaths []string) error {
	if f.blocklist != nil {
		if err := f.blocklist.Reload(blocklistPaths); err != nil {
			return err
		}
	}
	if f.allowlist != nil {
		if err := f.allowlist.Reload(allowlistPaths); err != nil {
			return err
		}
	}
	return nil
}

func (f *Filter) BlocklistLen() int {
	if f.blocklist == nil {
		return 0
	}
	return f.blocklist.Len()
}

func (f *Filter) AllowlistLen() int {
	if f.allowlist == nil {
		return 0
	}
	return f.allowlist.Len()
}
