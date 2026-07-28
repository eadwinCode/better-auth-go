package betterauth

import "testing"

func FuzzPluginPathMatching(f *testing.F) {
	f.Add("/documents/:id", "/documents/123")
	f.Add("/files/*rest", "/files/a/b")
	f.Add("/literal", "/other")
	f.Fuzz(func(t *testing.T, template, path string) {
		if len(template) > 2048 || len(path) > 2048 {
			t.Skip()
		}
		_, _, _ = pluginPathShape(template)
		_, _ = matchPluginPath(template, path)
		_ = templatesOverlap(template, path)
	})
}
