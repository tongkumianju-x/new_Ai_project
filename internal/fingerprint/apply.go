package fingerprint

// AssetLike 是为了避免依赖 scanner 包定义的最小接口。
// scanner.Asset 通过适配方法实现该接口（在 cmd 层做适配，保持依赖单向）。
type AssetLike interface {
	GetHostname() string
	GetServices() []ServiceView
	SetVendor(vendor, product, category string, tags []string)
}

// Apply 对一组资产执行指纹识别，把结果写回每个资产。
func (e *Engine) Apply(assets []AssetLike) {
	for _, a := range assets {
		view := AssetView{
			Hostname: a.GetHostname(),
			Services: a.GetServices(),
		}
		primary, hits := e.Match(view)
		var tags []string
		for _, h := range hits {
			tags = append(tags, h.RuleID)
		}
		category := string(primary.Category)
		a.SetVendor(primary.Vendor, primary.Product, category, tags)
	}
}
